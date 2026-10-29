// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use std::collections::BTreeMap;
use syn::visit::Visit;

const ADMISSION_CALL_CHIRHO: &str = "admit_served_dag_request_chirho(";
const DISPATCH_CALL_CHIRHO: &str = "dispatch_before_app_selection_chirho(";
const UNCONVERTED_CALL_CHIRHO: &str = "unconverted_elected_entrypoint_response_chirho(";
const SERVE_RUNTIME_SOURCE_PREFIX_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/";

fn reviewed_admission_population_chirho() -> BTreeMap<String, BTreeMap<String, usize>> {
    [
        (
            "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/app_http_chirho.rs",
            vec![
                ("admit_served_dag_request_chirho", 1),
                ("promote_ingress_chirho", 1),
            ],
        ),
        (
            "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/invoke_transport_chirho.rs",
            vec![("admit_served_dag_request_chirho", 2)],
        ),
        // NAMED-UNCONVERTED public run (it refuses on an elected era before selection), plus PROVEN READ-ONLY preview:
        // preview's admission (served-overload (ii)) is in-memory backpressure for the pure, non-persisting preview
        // executor, pinned by `preview_takes_admission_but_persists_nothing_chirho`.
        (
            "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/public_run_chirho.rs",
            vec![("admit_served_dag_request_chirho", 2)],
        ),
        (
            "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/ssr_web_chirho.rs",
            vec![("admit_served_dag_request_chirho", 1)],
        ),
        // The combined entry delegates to the same affine ingress and promotion stages.
        (
            "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/request_admission_chirho/served_request_abuse_gate_chirho.rs",
            vec![("admit_ingress_chirho", 1), ("promote_ingress_chirho", 1)],
        ),
        // CONVERTED: verified owner reentry takes origin/global custody before app/auth lookup.
        (
            "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/write_relay_chirho.rs",
            vec![("admit_relay_ingress_chirho", 1)],
        ),
        // CONVERTED: source ingress precedes dispatch; verified-principal promotion precedes execution.
        // Operated peer/proxy and mixed-version rollout evidence remains a separate F1 go-live gate.
        (
            "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/write_relay_chirho/pure_app_read_chirho.rs",
            vec![("admit_ingress_chirho", 1), ("promote_ingress_chirho", 1)],
        ),
    ]
    .into_iter()
    .map(|(path_chirho, calls_chirho)| {
        (
            path_chirho.to_string(),
            calls_chirho
                .into_iter()
                .map(|(name_chirho, count_chirho)| (name_chirho.to_string(), count_chirho))
                .collect(),
        )
    })
    .collect()
}

fn admission_call_population_chirho(source_chirho: &str) -> BTreeMap<String, usize> {
    let syntax_chirho = syn::parse_file(source_chirho).expect("parse served admission source");
    let mut population_chirho = ChirhoOwnedCallPopulationChirho::default();
    population_chirho.visit_file(&syntax_chirho);
    population_chirho.counts_chirho.retain(|name_chirho, _| {
        matches!(
            name_chirho.as_str(),
            "admit_served_dag_request_chirho"
                | "admit_ingress_chirho"
                | "admit_relay_ingress_chirho"
                | "promote_ingress_chirho"
        )
    });
    population_chirho.counts_chirho
}

fn ordered_once_chirho(source_chirho: &str, first_chirho: &str, second_chirho: &str) -> bool {
    let Some(first_index_chirho) = source_chirho.find(first_chirho) else {
        return false;
    };
    let Some(second_index_chirho) = source_chirho.find(second_chirho) else {
        return false;
    };
    first_index_chirho < second_index_chirho && source_chirho.matches(first_chirho).count() == 1
}

#[derive(Default)]
struct PathPopulationChirho {
    paths_chirho: Vec<Vec<String>>,
}

impl<'ast_chirho> Visit<'ast_chirho> for PathPopulationChirho {
    fn visit_expr_path(&mut self, path_chirho: &'ast_chirho syn::ExprPath) {
        self.paths_chirho.push(
            path_chirho
                .path
                .segments
                .iter()
                .map(|segment_chirho| segment_chirho.ident.to_string())
                .collect(),
        );
        syn::visit::visit_expr_path(self, path_chirho);
    }
}

#[derive(Default)]
struct ChirhoOwnedCallPopulationChirho {
    counts_chirho: BTreeMap<String, usize>,
}

impl ChirhoOwnedCallPopulationChirho {
    fn record_chirho(&mut self, name_chirho: &syn::Ident) {
        let name_chirho = name_chirho.to_string();
        if name_chirho.ends_with("_chirho") {
            *self.counts_chirho.entry(name_chirho).or_insert(0) += 1;
        }
    }
}

impl<'ast_chirho> Visit<'ast_chirho> for ChirhoOwnedCallPopulationChirho {
    fn visit_expr_call(&mut self, call_chirho: &'ast_chirho syn::ExprCall) {
        if let syn::Expr::Path(path_chirho) = call_chirho.func.as_ref() {
            if let Some(segment_chirho) = path_chirho.path.segments.last() {
                self.record_chirho(&segment_chirho.ident);
            }
        }
        syn::visit::visit_expr_call(self, call_chirho);
    }

    fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
        self.record_chirho(&call_chirho.method);
        syn::visit::visit_expr_method_call(self, call_chirho);
    }
}

#[derive(Default)]
struct LiveAppendReferencePopulationChirho {
    prepare_references_chirho: usize,
    finalize_references_chirho: usize,
}

impl<'ast_chirho> Visit<'ast_chirho> for LiveAppendReferencePopulationChirho {
    fn visit_expr_path(&mut self, path_chirho: &'ast_chirho syn::ExprPath) {
        if let Some(segment_chirho) = path_chirho.path.segments.last() {
            match segment_chirho.ident.to_string().as_str() {
                "prepare_append_chirho" => self.prepare_references_chirho += 1,
                "finalize_append_chirho" => self.finalize_references_chirho += 1,
                _ => {}
            }
        }
        syn::visit::visit_expr_path(self, path_chirho);
    }

    fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
        match call_chirho.method.to_string().as_str() {
            "prepare_append_chirho" => self.prepare_references_chirho += 1,
            "finalize_append_chirho" => self.finalize_references_chirho += 1,
            _ => {}
        }
        syn::visit::visit_expr_method_call(self, call_chirho);
    }
}

fn function_path_population_chirho(
    source_chirho: &str,
    function_name_chirho: &str,
) -> Vec<Vec<String>> {
    let syntax_chirho = syn::parse_file(source_chirho).expect("parse guarded composition source");
    let function_chirho = syntax_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            syn::Item::Fn(function_chirho) if function_chirho.sig.ident == function_name_chirho => {
                Some(function_chirho)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("guarded function moved or disappeared: {function_name_chirho}"));
    let mut population_chirho = PathPopulationChirho::default();
    population_chirho.visit_block(&function_chirho.block);
    population_chirho.paths_chirho
}

fn function_chirho_owned_call_population_chirho(
    source_chirho: &str,
    function_name_chirho: &str,
) -> BTreeMap<String, usize> {
    let syntax_chirho = syn::parse_file(source_chirho).expect("parse guarded composition source");
    let function_chirho = syntax_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            syn::Item::Fn(function_chirho) if function_chirho.sig.ident == function_name_chirho => {
                Some(function_chirho)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("guarded function moved or disappeared: {function_name_chirho}"));
    let mut population_chirho = ChirhoOwnedCallPopulationChirho::default();
    population_chirho.visit_block(&function_chirho.block);
    population_chirho.counts_chirho
}

fn path_suffix_count_chirho(paths_chirho: &[Vec<String>], suffix_chirho: &[&str]) -> usize {
    paths_chirho
        .iter()
        .filter(|path_chirho| {
            path_chirho.len() >= suffix_chirho.len()
                && path_chirho[path_chirho.len() - suffix_chirho.len()..]
                    .iter()
                    .map(String::as_str)
                    .eq(suffix_chirho.iter().copied())
        })
        .count()
}

fn has_cfg_feature_chirho(attrs_chirho: &[syn::Attribute], feature_chirho: &str) -> bool {
    attrs_chirho.iter().any(|attr_chirho| {
        attr_chirho.path().is_ident("cfg")
            && matches!(
                &attr_chirho.meta,
                syn::Meta::List(list_chirho)
                    if list_chirho.tokens.to_string()
                        == format!("feature = \"{feature_chirho}\"")
            )
    })
}

fn use_tree_contains_chirho(tree_chirho: &syn::UseTree, name_chirho: &str) -> bool {
    match tree_chirho {
        syn::UseTree::Path(path_chirho) => use_tree_contains_chirho(&path_chirho.tree, name_chirho),
        syn::UseTree::Name(item_chirho) => item_chirho.ident == name_chirho,
        syn::UseTree::Rename(item_chirho) => item_chirho.rename == name_chirho,
        syn::UseTree::Group(group_chirho) => group_chirho
            .items
            .iter()
            .any(|item_chirho| use_tree_contains_chirho(item_chirho, name_chirho)),
        syn::UseTree::Glob(_) => false,
    }
}

#[test]
fn production_and_testkind_voters_select_distinct_placement_admissions_chirho() {
    const FEATURE_CHIRHO: &str = "testkind-roster-wide-admission-chirho";
    const TESTKIND_FUNCTION_CHIRHO: &str = "serve_testkind_roster_wide_gd7_voter_geo_node_chirho";
    let root_chirho = workspace_root_chirho();
    let geo_source_chirho = std::fs::read_to_string(
        root_chirho.join("crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/lib.rs"),
    )
    .expect("read geo composition root");
    let geo_syntax_chirho =
        syn::parse_file(&geo_source_chirho).expect("parse geo composition root");

    let gated_modules_chirho = geo_syntax_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            syn::Item::Mod(module_chirho)
                if module_chirho.ident == "testkind_roster_wide_admission_chirho" =>
            {
                Some(module_chirho)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(gated_modules_chirho.len(), 1);
    assert!(has_cfg_feature_chirho(
        &gated_modules_chirho[0].attrs,
        FEATURE_CHIRHO
    ));

    let gated_exports_chirho = geo_syntax_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            syn::Item::Use(use_chirho)
                if matches!(use_chirho.vis, syn::Visibility::Public(_))
                    && use_tree_contains_chirho(&use_chirho.tree, TESTKIND_FUNCTION_CHIRHO) =>
            {
                Some(use_chirho)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(gated_exports_chirho.len(), 1);
    assert!(has_cfg_feature_chirho(
        &gated_exports_chirho[0].attrs,
        FEATURE_CHIRHO
    ));

    let production_paths_chirho = function_path_population_chirho(
        &geo_source_chirho,
        "serve_resident_gd7_voter_geo_node_with_resident_opener_and_local_owner_sidecar_chirho",
    );
    assert_eq!(
        path_suffix_count_chirho(
            &production_paths_chirho,
            &[
                "GeoVoterPlacementAdmissionChirho",
                "ProductionRequiredChirho"
            ]
        ),
        1,
        "the production voter wrapper must select the production-required placement policy"
    );
    assert_eq!(
        path_suffix_count_chirho(
            &production_paths_chirho,
            &[
                "GeoVoterPlacementAdmissionChirho",
                "ExplicitTestkindRosterWideChirho"
            ]
        ),
        0,
        "the production voter wrapper must never select the test-kind roster-wide admission"
    );

    let testkind_admission_source_chirho = std::fs::read_to_string(root_chirho.join(
        "crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/tenant_placement_chirho/testkind_roster_wide_admission_chirho.rs",
    ))
    .expect("read feature-gated test-kind admission");
    let testkind_paths_chirho = function_path_population_chirho(
        &testkind_admission_source_chirho,
        TESTKIND_FUNCTION_CHIRHO,
    );
    assert_eq!(
        path_suffix_count_chirho(
            &testkind_paths_chirho,
            &[
                "GeoVoterPlacementAdmissionChirho",
                "ExplicitTestkindRosterWideChirho"
            ]
        ),
        1,
        "the feature-gated test-kind wrapper must select its explicit admission"
    );
    assert_eq!(
        path_suffix_count_chirho(
            &testkind_paths_chirho,
            &[
                "GeoVoterPlacementAdmissionChirho",
                "ProductionRequiredChirho"
            ]
        ),
        0,
        "the test-kind compatibility wrapper must not silently fall back to production admission"
    );

    let testkind_main_chirho = std::fs::read_to_string(
        root_chirho.join("crates/ledger-chirho/cairn-ledger-geo-node-testkind-chirho/src/main.rs"),
    )
    .expect("read test-kind binary entry point");
    let main_paths_chirho = function_path_population_chirho(&testkind_main_chirho, "main");
    assert_eq!(
        path_suffix_count_chirho(&main_paths_chirho, &[TESTKIND_FUNCTION_CHIRHO]),
        1,
        "the separate test-kind binary must call the feature-gated compatibility wrapper"
    );
    assert_eq!(
        path_suffix_count_chirho(
            &main_paths_chirho,
            &["serve_resident_gd7_voter_geo_node_with_resident_opener_and_local_owner_sidecar_chirho"]
        ),
        0,
        "the test-kind binary must not select the production-required wrapper"
    );

    let placement_testkind_main_chirho = std::fs::read_to_string(root_chirho.join(
        "crates/ledger-chirho/cairn-ledger-geo-node-testkind-chirho/src/bin/cairn-ledger-geo-node-placement-testkind-chirho.rs",
    ))
    .expect("read placement-admitted test-kind binary entry point");
    let placement_main_paths_chirho =
        function_path_population_chirho(&placement_testkind_main_chirho, "main");
    assert_eq!(
        path_suffix_count_chirho(
            &placement_main_paths_chirho,
            &["serve_resident_gd7_voter_geo_node_with_resident_opener_and_local_owner_sidecar_chirho"]
        ),
        1,
        "the placement test-kind binary must select production-required placement admission"
    );
    assert_eq!(
        path_suffix_count_chirho(&placement_main_paths_chirho, &[TESTKIND_FUNCTION_CHIRHO]),
        0,
        "the placement test-kind binary must never select roster-wide compatibility admission"
    );

    let geo_manifest_chirho: toml::Value = std::fs::read_to_string(
        root_chirho.join("crates/ledger-chirho/cairn-ledger-geo-node-chirho/Cargo.toml"),
    )
    .expect("read geo manifest")
    .parse()
    .expect("parse geo manifest");
    let default_features_chirho = geo_manifest_chirho["features"]["default"]
        .as_array()
        .expect("geo default feature array");
    assert!(
        !default_features_chirho
            .iter()
            .any(|entry_chirho| entry_chirho.as_str() == Some(FEATURE_CHIRHO)),
        "the roster-wide compatibility admission must stay out of production defaults"
    );

    let testkind_manifest_chirho: toml::Value = std::fs::read_to_string(
        root_chirho.join("crates/ledger-chirho/cairn-ledger-geo-node-testkind-chirho/Cargo.toml"),
    )
    .expect("read test-kind manifest")
    .parse()
    .expect("parse test-kind manifest");
    let selected_features_chirho = testkind_manifest_chirho["dependencies"]
        ["cairn-ledger-geo-node-chirho"]["features"]
        .as_array()
        .expect("test-kind geo feature array");
    assert_eq!(
        selected_features_chirho
            .iter()
            .filter(|entry_chirho| entry_chirho.as_str() == Some(FEATURE_CHIRHO))
            .count(),
        1,
        "only the separate test-kind package should explicitly select roster-wide admission"
    );
}

#[test]
fn served_dag_admission_population_stays_explicitly_classified_chirho() {
    let expected_chirho = reviewed_admission_population_chirho();
    let mut actual_chirho = BTreeMap::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        if !relative_chirho.starts_with(SERVE_RUNTIME_SOURCE_PREFIX_CHIRHO) {
            continue;
        }
        let raw_source_chirho =
            std::fs::read_to_string(&path_chirho).expect("read served runtime source");
        let source_chirho = production_text_chirho(&raw_source_chirho);
        let calls_chirho = admission_call_population_chirho(&source_chirho);
        if !calls_chirho.is_empty() {
            actual_chirho.insert(relative_chirho, calls_chirho);
        }
    }
    assert_eq!(
        actual_chirho, expected_chirho,
        "a new or moved served-DAG admission site must be classified as converted, proven read-only, or named-unconverted before it can land"
    );
}

#[test]
fn converted_app_route_dispatches_before_any_ref_or_body_policy_lookup_chirho() {
    let source_chirho = std::fs::read_to_string(workspace_root_chirho().join(
        "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/app_http_chirho.rs",
    ))
    .expect("read direct app route source");
    let core_chirho = source_chirho
        .split("async fn run_app_http_with_method_for_served_request_and_uri_chirho(")
        .nth(1)
        .expect("direct app route core");
    assert!(
        ordered_once_chirho(core_chirho, DISPATCH_CALL_CHIRHO, "load_refs_chirho()"),
        "the elected credits route must dispatch after admission and before its first ref load"
    );
    assert!(
        ordered_once_chirho(
            core_chirho,
            DISPATCH_CALL_CHIRHO,
            "direct_route_rejects_request_body_chirho("
        ),
        "the elected credits POST must dispatch before its route/body-policy lookup"
    );
}

#[test]
fn converted_elected_ssr_read_is_capability_and_local_authority_bound_chirho() {
    let source_chirho = std::fs::read_to_string(workspace_root_chirho().join(
        "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/ssr_web_chirho.rs",
    ))
    .expect("read converted SSR source");
    assert_eq!(
        source_chirho.matches(UNCONVERTED_CALL_CHIRHO).count(),
        0,
        "the converted SSR road must not retain the old unconditional elected-era refusal"
    );

    let handler_chirho = source_chirho
        .split("pub(super) async fn ssr_get_chirho(")
        .nth(1)
        .expect("converted SSR handler")
        .split("\nfn begin_ssr_read_authority_chirho(")
        .next()
        .expect("bound converted SSR handler");
    let begin_chirho = handler_chirho
        .find("begin_ssr_read_authority_chirho(")
        .expect("one SSR authority begin");
    let load_chirho = handler_chirho
        .find("load_refs_chirho()")
        .expect("one SSR ref load");
    let select_chirho = handler_chirho
        .find("select_app_dag_without_resource_usage_chirho(")
        .expect("one no-usage SSR DAG selection");
    let classify_chirho = handler_chirho
        .find("elected_ssr_selected_dag_refusal_chirho(")
        .expect("one selected-DAG capability classification");
    let input_chirho = handler_chirho
        .find("app_dag_input_chirho(")
        .expect("one SSR DAG input build");
    let confirmations_chirho = handler_chirho
        .match_indices("confirm_ssr_read_authority_chirho(")
        .map(|(index_chirho, _match_chirho)| index_chirho)
        .collect::<Vec<_>>();
    let execute_chirho = handler_chirho
        .find("try_run_served_with_context_chirho(")
        .expect("one SSR DAG execution");
    let render_chirho = handler_chirho
        .find("html_lower_chirho(")
        .expect("one SSR payload render");
    assert_eq!(
        handler_chirho
            .matches("begin_ssr_read_authority_chirho(")
            .count(),
        1
    );
    assert_eq!(
        handler_chirho
            .matches("elected_ssr_selected_dag_refusal_chirho(")
            .count(),
        1
    );
    assert_eq!(confirmations_chirho.len(), 2);
    assert!(
        handler_chirho.contains("SsrReadAuthorityChirho::LocalChirho =>")
            && handler_chirho.contains("select_app_dag_with_resource_gate_chirho(")
            && handler_chirho.contains("SsrReadAuthorityChirho::ElectedChirho(_) =>")
            && handler_chirho.contains("select_app_dag_without_resource_usage_chirho("),
        "local SSR must retain resource metering while elected SSR uses the no-usage selector"
    );
    assert!(
        begin_chirho < load_chirho
            && load_chirho < select_chirho
            && select_chirho < classify_chirho
            && classify_chirho < input_chirho
            && input_chirho < confirmations_chirho[0]
            && confirmations_chirho[0] < execute_chirho
            && execute_chirho < confirmations_chirho[1]
            && confirmations_chirho[1] < render_chirho,
        "SSR must witness authority before selection, classify before execution, and confirm both immediately before execution and before payload release"
    );

    let classification_chirho = source_chirho
        .split("fn elected_ssr_selected_dag_refusal_chirho(")
        .nth(1)
        .expect("selected SSR DAG classification")
        .split("\nfn confirm_ssr_read_authority_chirho(")
        .next()
        .expect("bound selected SSR DAG classification");
    assert!(
        classification_chirho.contains("dag_is_elected_ssr_read_only_chirho(")
            && classification_chirho.contains("RelayMutationFamilyUnconvertedChirho")
            && classification_chirho.contains("DefinitelyNotExecutedChirho"),
        "a non-read capability must retain the fixed pre-execution mutation-family refusal"
    );

    let resource_source_chirho = std::fs::read_to_string(
        workspace_root_chirho()
            .join("crates/cairn-serve-runtime-chirho/src/serve_chirho/resource_gate_chirho.rs"),
    )
    .expect("read request resource-gate source");
    let no_usage_selection_chirho = resource_source_chirho
        .split("pub(super) fn select_app_dag_without_resource_usage_chirho(")
        .nth(1)
        .expect("no-usage app selection")
        .split("\npub(super) fn select_app_dag_with_resource_gate_chirho(")
        .next()
        .expect("bound no-usage app selection");
    assert!(
        no_usage_selection_chirho
            .contains("app_request_resource_gate_anonymous_allowed_chirho(")
            && no_usage_selection_chirho.contains("return Ok(None)")
            && no_usage_selection_chirho.contains("default_app_selection_chirho("),
        "no-usage selection must refuse an active request resource gate before direct app selection"
    );
    assert!(
        !no_usage_selection_chirho.contains("record_request_resource_usage_chirho(")
            && !no_usage_selection_chirho.contains("select_app_dag_with_resource_gate_chirho("),
        "no-usage selection must not directly invoke either known request-usage append road"
    );
    assert_eq!(
        function_chirho_owned_call_population_chirho(
            &resource_source_chirho,
            "select_app_dag_without_resource_usage_chirho",
        ),
        BTreeMap::from([
            (
                "app_request_resource_gate_anonymous_allowed_chirho".to_string(),
                1,
            ),
            ("default_app_selection_chirho".to_string(), 1),
        ]),
        "the no-usage selector's Chirho-owned direct-call frontier changed; the two existing callees are separately reviewed read-only boundaries, and every new callee requires classification"
    );
}

/// The text of one top-level function, from its signature to its closing brace at column 0 (rustfmt layout).
fn top_level_function_chirho<'a>(source_chirho: &'a str, signature_chirho: &str) -> &'a str {
    let start_chirho = source_chirho
        .find(signature_chirho)
        .unwrap_or_else(|| panic!("missing {signature_chirho}"));
    let tail_chirho = &source_chirho[start_chirho..];
    let end_chirho = tail_chirho
        .find("\n}\n")
        .unwrap_or_else(|| panic!("unterminated {signature_chirho}"));
    &tail_chirho[..end_chirho + 2]
}

#[test]
fn current_unconverted_entrypoints_refuse_before_their_first_selection_read_chirho() {
    let root_chirho = workspace_root_chirho();
    // The public run is scoped to its own handler: the same file's preview admission is classified PROVEN READ-ONLY in
    // the population above, and the elected-era refusal belongs to the public RUN (served-overload (ii)).
    for (relative_chirho, expected_sites_chirho, first_selection_chirho, scope_chirho) in [
        (
            "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/public_run_chirho.rs",
            1,
            "parse_content_hash_chirho(",
            Some("async fn run_dag_http_chirho("),
        ),
        (
            "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/invoke_transport_chirho.rs",
            2,
            "invoke_critical_chirho(",
            None,
        ),
    ] {
        let file_chirho = std::fs::read_to_string(root_chirho.join(relative_chirho))
            .expect("read classified served entrypoint");
        let source_chirho = match scope_chirho {
            Some(signature_chirho) => top_level_function_chirho(&file_chirho, signature_chirho),
            None => file_chirho.as_str(),
        };
        assert_eq!(
            source_chirho.matches(UNCONVERTED_CALL_CHIRHO).count(),
            expected_sites_chirho,
            "{relative_chirho} must retain one elected-era named refusal per admitted entrypoint"
        );
        let admitted_tails_chirho = source_chirho
            .split(ADMISSION_CALL_CHIRHO)
            .skip(1)
            .collect::<Vec<_>>();
        assert_eq!(admitted_tails_chirho.len(), expected_sites_chirho);
        for admitted_tail_chirho in admitted_tails_chirho {
            assert!(
                admitted_tail_chirho.find(UNCONVERTED_CALL_CHIRHO)
                    < admitted_tail_chirho.find(first_selection_chirho),
                "{relative_chirho} must refuse after admission and before selection or execution"
            );
        }
    }

    let domain_source_chirho = std::fs::read_to_string(root_chirho.join(
        "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/app_http_chirho.rs",
    ))
    .expect("read domain fallback source");
    let domain_chirho = domain_source_chirho
        .split("pub(super) async fn domain_binding_fallback_chirho(")
        .nth(1)
        .expect("domain fallback");
    assert!(
        ordered_once_chirho(
            domain_chirho,
            UNCONVERTED_CALL_CHIRHO,
            "verified_domain_bindings_chirho()"
        ),
        "elected domain fallback must refuse before reading its binding table"
    );
}

#[test]
fn relay_order_guard_rejects_a_dispatch_after_ref_selection_chirho() {
    let tampered_chirho = r#"
        let refs_chirho = runtime_chirho.load_refs_chirho()?;
        dispatch_before_app_selection_chirho(state_chirho).await;
    "#;
    assert!(
        !ordered_once_chirho(tampered_chirho, DISPATCH_CALL_CHIRHO, "load_refs_chirho()"),
        "the guard's planted reverse ordering must fail"
    );
}

#[test]
fn relay_only_follower_startup_neither_recovers_intents_nor_runs_the_monitor_chirho() {
    let serve_source_chirho = std::fs::read_to_string(
        workspace_root_chirho().join("crates/cairn-serve-runtime-chirho/src/serve_chirho.rs"),
    )
    .expect("read served runtime root");
    let startup_source_chirho = std::fs::read_to_string(workspace_root_chirho().join(
        "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_lifecycle_chirho/startup_chirho.rs",
    ))
    .expect("read served runtime startup");
    let helper_chirho = startup_source_chirho
        .split("fn resume_projection_run_intents_for_startup_posture_chirho(")
        .nth(1)
        .expect("relay-aware startup recovery helper");
    assert!(
        helper_chirho
            .find("ConfiguredServeStartupPostureChirho::RecoverRunIntentsAndMonitorChirho")
            < helper_chirho.find("resume_unfinished_run_intents_with_projection_read_chirho("),
        "startup recovery must remain positively gated on the normal mutation posture"
    );
    let monitor_chirho = serve_source_chirho
        .split("let ledger_monitor_chirho = match startup_posture_chirho")
        .nth(1)
        .expect("relay-aware monitor composition");
    assert!(
        monitor_chirho.find("ConfiguredServeStartupPostureChirho::RelayOnlyFollowerChirho => None")
            < monitor_chirho.find("serve_with_options_until_chirho("),
        "relay-only followers must not append periodic monitor evidence"
    );
    assert!(
        serve_source_chirho.contains("RelayOnlyFollowerRequiresElectedRootChirho")
            && serve_source_chirho
                .contains("RelayOnlyFollowerStartupCompositionInvalidChirho"),
        "the no-recovery posture must require an elected root, both relay ports, and no effect runtime"
    );

    let geo_source_chirho = std::fs::read_to_string(
        workspace_root_chirho()
            .join("crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/lib.rs"),
    )
    .expect("read geo-node composition");
    let runtime_port_selection_chirho = geo_source_chirho
        .split("let runtime_ports_chirho = match startup_role_chirho {")
        .nth(1)
        .and_then(|remainder_chirho| {
            remainder_chirho
                .split("let served_request_limits_chirho")
                .next()
        })
        .expect("runtime-port startup-role selection");
    let compact_selection_chirho = runtime_port_selection_chirho
        .split_whitespace()
        .collect::<String>();
    let relay_only_arm_chirho = concat!(
        "GeoVoterStartupRoleChirho::NonResidentChirho(_)=>{",
        "runtime_ports_chirho.with_relay_only_follower_startup_chirho()?}"
    );
    assert!(
        compact_selection_chirho.contains(relay_only_arm_chirho),
        "every nonresident runtime must adopt the zero-write startup posture before serving"
    );
    assert_eq!(
        compact_selection_chirho
            .matches("GeoVoterStartupRoleChirho::NonResidentChirho")
            .count(),
        1,
        "the exhaustive startup-posture selection must classify the nonresident state exactly once"
    );
}

#[test]
fn geo_writer_era_activation_uses_only_the_resident_shared_elector_authority_chirho() {
    let root_chirho = workspace_root_chirho();
    let geo_source_chirho = std::fs::read_to_string(
        root_chirho.join("crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/lib.rs"),
    )
    .expect("read geo-node composition");
    let admitted_serve_chirho = geo_source_chirho
        .split("fn serve_resident_gd7_voter_geo_node_with_admission_chirho(")
        .nth(1)
        .expect("production voter admission composition");
    let placement_policy_index_chirho = admitted_serve_chirho
        .find("verify_geo_voter_startup_policy_chirho(")
        .expect("production voter verifies placement startup policy");
    let transport_bind_index_chirho = admitted_serve_chirho
        .find("TcpListener::bind(verified_listen_addr_chirho)")
        .expect("production voter binds the private cluster transport");
    assert!(
        placement_policy_index_chirho < transport_bind_index_chirho,
        "production placement/root-wide admission must refuse before the private transport binds"
    );
    let admitted_paths_chirho = function_path_population_chirho(
        &geo_source_chirho,
        "serve_resident_gd7_voter_geo_node_with_admission_chirho",
    );
    assert_eq!(
        path_suffix_count_chirho(
            &admitted_paths_chirho,
            &["select_geo_resident_startup_chirho"],
        ),
        1,
        "the production serve path must traverse the exhaustive resident-role selector exactly once"
    );
    assert_eq!(
        path_suffix_count_chirho(&admitted_paths_chirho, &["open_resident_chirho"]),
        1,
        "the production serve path must supply exactly one resident-opening closure to its selector"
    );
    let selector_index_chirho = admitted_serve_chirho
        .find("select_geo_resident_startup_chirho(")
        .expect("production serve path selects resident startup by role");
    let open_index_chirho = admitted_serve_chirho
        .find("open_resident_chirho(")
        .expect("the injected resident opener opens the resident actor");
    assert!(
        admitted_serve_chirho.contains("&authority_composition_chirho"),
        "the selected local-owner opening closure must thread the checked A6 composition authority into the opener"
    );
    let activation_index_chirho = admitted_serve_chirho
        .find("activate_fresh_writer_era_chirho(")
        .expect("fresh writer era activates");
    let ready_index_chirho = admitted_serve_chirho
        .find("mark_local_authority_ready_chirho()")
        .expect("relay local authority becomes ready");
    assert!(
        selector_index_chirho < open_index_chirho
            && open_index_chirho < activation_index_chirho
            && activation_index_chirho < ready_index_chirho,
        "selection must invoke the resident opener before activation and before relay execution becomes ready"
    );
    assert!(
        admitted_serve_chirho.contains("resident_chirho.head_transition_authority_chirho()"),
        "the production activation call must consume the resident shared-elector authority adapter"
    );

    let mut selector_callers_chirho = BTreeMap::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let raw_source_chirho =
            std::fs::read_to_string(&path_chirho).expect("read production Rust source");
        let production_source_chirho = production_text_chirho(&raw_source_chirho);
        let syntax_chirho = syn::parse_file(&production_source_chirho)
            .unwrap_or_else(|_| panic!("parse {}", workspace_relative_chirho(&path_chirho)));
        let mut population_chirho = PathPopulationChirho::default();
        population_chirho.visit_file(&syntax_chirho);
        let count_chirho = path_suffix_count_chirho(
            &population_chirho.paths_chirho,
            &["select_geo_resident_startup_chirho"],
        );
        if count_chirho > 0 {
            selector_callers_chirho.insert(workspace_relative_chirho(&path_chirho), count_chirho);
        }
    }
    assert_eq!(
        selector_callers_chirho,
        BTreeMap::from([(
            "crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/lib.rs".to_string(),
            1,
        )]),
        "the exhaustive resident-role selector must have exactly one production caller, the shipping geo serve path"
    );

    let authority_composition_source_chirho = std::fs::read_to_string(root_chirho.join(
        "crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/a6_authority_composition_chirho.rs",
    ))
    .expect("read explicit A6 authority composition");
    assert!(
        geo_source_chirho.contains(
            "A6GeoResidentAuthorityCompositionChirho::from_cluster_node_chirho(&cluster_node_chirho)",
        ) && geo_source_chirho
            .contains("Arc::clone(authority_composition_chirho.elector_chirho())"),
        "the served path must select and retain the exact checked ClusterNode elector"
    );
    assert_eq!(
        authority_composition_source_chirho
            .matches("open_resident_effect_journal_handle_with_shared_elector_chirho")
            .count(),
        2,
        "the A6 boundary must import and call exactly one shared-elector opener"
    );
    let mut shared_elector_opener_references_chirho = BTreeMap::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let raw_source_chirho =
            std::fs::read_to_string(&path_chirho).expect("read production Rust source");
        let production_source_chirho = production_text_chirho(&raw_source_chirho);
        let syntax_chirho = syn::parse_file(&production_source_chirho)
            .unwrap_or_else(|_| panic!("parse {}", workspace_relative_chirho(&path_chirho)));
        let mut population_chirho = PathPopulationChirho::default();
        population_chirho.visit_file(&syntax_chirho);
        let count_chirho = path_suffix_count_chirho(
            &population_chirho.paths_chirho,
            &["open_resident_effect_journal_handle_with_shared_elector_chirho"],
        );
        if count_chirho > 0 {
            shared_elector_opener_references_chirho
                .insert(workspace_relative_chirho(&path_chirho), count_chirho);
        }
    }
    assert_eq!(
        shared_elector_opener_references_chirho,
        BTreeMap::from([(
            "crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/a6_authority_composition_chirho.rs"
                .to_string(),
            1,
        )]),
        "the lower-level shared-elector opener must have exactly one production reference, inside the mirror-required A6 composition; another reference creates an unmirrored resident door"
    );
    assert!(
        !authority_composition_source_chirho
            .contains("open_resident_effect_journal_handle_chirho("),
        "the A6 boundary must have no ordinary single-voter fallback"
    );
    assert_eq!(
        geo_source_chirho
            .matches(".open_resident_effect_journal_chirho(")
            .count(),
        0,
        "production geo composition must not add a second permissive unmirrored resident door"
    );
    assert_eq!(
        geo_source_chirho
            .matches("open_resident_effect_journal_handle_with_shared_elector_chirho")
            .count(),
        0,
        "production geo composition must reach the shared elector only through the mirror-required A6 door"
    );
    assert_eq!(
        authority_composition_source_chirho
            .matches("pub fn open_resident_effect_journal_chirho(")
            .count(),
        0,
        "the A6 composition must expose no permissive unmirrored resident opener"
    );
    assert!(
        authority_composition_source_chirho
            .contains("mirror_runtime_chirho: LedgerMirrorRuntimePortsChirho"),
        "the private A6 funnel must require the paired append-and-recovery runtime rather than retain an Option-based unmirrored path"
    );
    assert_eq!(
        authority_composition_source_chirho
            .matches("fn install_mirror_runtime_chirho(")
            .count(),
        1,
        "the A6 composition must retain exactly one private paired mirror-runtime installer"
    );
    assert_eq!(
        authority_composition_source_chirho
            .matches("pub fn install_mirror_runtime_chirho(")
            .count(),
        0,
        "production callers must not be able to install arbitrary append or recovery ports after composition"
    );
    // Item 6.5-a seam: the checked provider-LESS door choice moved from an inline call into the
    // production default opener. Item 7 additionally requires that door to refuse unless the
    // placement-bound mirror was installed before resident composition.
    assert!(
        geo_source_chirho.contains("fn default_resident_opener_chirho(")
            && geo_source_chirho
                .contains("authority_composition_chirho.open_required_mirrored_resident_effect_journal_chirho("),
        "production's default resident opener must require the placement-bound mirror before using the checked A6 provider-less shared-elector door"
    );
    assert!(
        geo_source_chirho
            .matches(".install_configured_append_mirror_chirho(")
            .count()
            == 1
            && authority_composition_source_chirho
                .matches("pub(crate) fn install_configured_append_mirror_chirho(")
                .count()
                == 1
            && authority_composition_source_chirho
                .matches("self.install_mirror_runtime_chirho(")
                .count()
                == 1
            && geo_source_chirho
                .matches("verified_placement_startup_chirho.resident_placement_chirho()")
                .count()
                == 1
            && authority_composition_source_chirho.contains("A6GeoMirrorRuntimeRequiredChirho"),
        "the sole production mirror installer must consume the verified assigned-voter placement, install both runtime ports, and retain the shipping refusal when placement is absent"
    );

    // Reviewer-chosen arm (claude2_chirho, geo-proof review): the runtime WIRING is the one seam
    // the composition pins above do not reach. The plain runtime variant internally opens the
    // ordinary single-voter actor; if the geo serve ever swapped to it, a second self-elected
    // actor would stand beside the composed one. Pin the wiring choice structurally.
    assert!(
        geo_source_chirho.contains(
            "open_shared_ledger_host_postgres_effect_runtime_with_resident_journal_chirho(",
        ),
        "the geo runtime wiring must compose around the already-open composed resident actor"
    );
    assert_eq!(
        geo_source_chirho
            .matches("open_shared_ledger_host_postgres_effect_runtime_chirho(")
            .count(),
        0,
        "the geo serve path must never call the plain runtime variant, whose internal ordinary opener would mint a second self-elected single-voter actor"
    );

    let activation_source_chirho = std::fs::read_to_string(root_chirho.join(
        "crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/writer_era_activation_chirho.rs",
    ))
    .expect("read writer-era activation source");
    assert!(
        !activation_source_chirho.contains("issue_elected_writer_fence_chirho(")
            && !activation_source_chirho.contains("issue_elected_writer_fence_for_root_chirho("),
        "activation must not bypass the live authority port with a direct or test-only fence mint"
    );
    assert!(
        activation_source_chirho.contains("GeoWriterEraNotActivatedChirho")
            && activation_source_chirho.contains("cluster_config_blake3_chirho")
            && activation_source_chirho.contains("roster_head_blake3_chirho"),
        "fresh followers must refuse and the signed record must bind parsed config plus roster head"
    );
}

#[test]
fn recovery_prefix_transfer_has_no_live_append_prepare_or_finalize_reach_chirho() {
    const RECOVERY_SOURCE_PREFIX_CHIRHO: &str =
        "crates/stores-chirho/cairn-ledger-mirror-http-chirho/src/recovery_chirho";
    let mut recovery_sources_chirho = BTreeMap::new();
    let mut live_append_references_chirho = BTreeMap::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        if !relative_chirho.starts_with(RECOVERY_SOURCE_PREFIX_CHIRHO) {
            continue;
        }
        let raw_source_chirho =
            std::fs::read_to_string(&path_chirho).expect("read recovery production source");
        let production_source_chirho = production_text_chirho(&raw_source_chirho);
        let syntax_chirho = syn::parse_file(&production_source_chirho)
            .unwrap_or_else(|_| panic!("parse recovery production source {relative_chirho}"));
        let mut population_chirho = LiveAppendReferencePopulationChirho::default();
        population_chirho.visit_file(&syntax_chirho);
        recovery_sources_chirho.insert(relative_chirho.clone(), 1usize);
        let total_chirho = population_chirho.prepare_references_chirho
            + population_chirho.finalize_references_chirho;
        if total_chirho > 0 {
            live_append_references_chirho.insert(relative_chirho, total_chirho);
        }
    }
    assert!(
        recovery_sources_chirho.len() >= 5,
        "the recovery transfer census must fail closed if its production module population disappears: {recovery_sources_chirho:?}"
    );
    assert!(
        live_append_references_chirho.is_empty(),
        "verified-prefix recovery must transfer one signed historical closure, never replay history through live prepare_append/finalize_append: {live_append_references_chirho:?}"
    );
}

#[test]
fn relay_only_follower_router_is_default_deny_before_every_unconverted_handler_chirho() {
    let root_chirho = workspace_root_chirho();
    let serve_source_chirho = std::fs::read_to_string(
        root_chirho.join("crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_lifecycle_chirho/startup_chirho.rs"),
    )
    .expect("read served runtime root");
    let router_tail_chirho = serve_source_chirho
        .split("fn router_for_state_chirho(")
        .nth(1)
        .expect("runtime router constructor");
    // The relay guard wraps the complete router, set just before it with its fallback and state, so it runs before any
    // handler. The one layer outside it is K2's answer-cache layer: a response mapper that calls the guarded router and
    // rewrites only the answer's Cache-Control, so it runs no handler of its own (PFE #26536, #26589).
    assert!(
        router_tail_chirho.contains(
            ".fallback(domain_binding_fallback_chirho)\n        .with_state(state_chirho);\n    let app_chirho = if relay_only_follower_chirho {\n        app_chirho.layer(axum::middleware::from_fn(\n            write_relay_chirho::relay_only_follower_route_guard_chirho,\n        ))\n    } else {\n        app_chirho\n    };\n"
        ),
        "relay-only startup must wrap the complete router, including its fallback, before any handler can run"
    );
    let outside_relay_chirho = router_tail_chirho
        .split("    } else {\n        app_chirho\n    };\n")
        .nth(1)
        .and_then(|rest_chirho| rest_chirho.split("\n}\n").next())
        .expect("the router constructor's tail after the relay-only branch");
    assert!(
        outside_relay_chirho.ends_with(
            "    Ok(app_chirho.layer(axum::middleware::map_response(\n        answer_cache_chirho::finalize_answer_cache_chirho,\n    )))"
        ) && outside_relay_chirho.matches(".layer(").count() == 1,
        "the only layer outside the relay guard is the answer-cache response mapper, which runs no handler: {outside_relay_chirho}"
    );

    let relay_source_chirho = std::fs::read_to_string(root_chirho.join(
        "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/write_relay_chirho.rs",
    ))
    .expect("read served relay boundary");
    let guard_tail_chirho = relay_source_chirho
        .split("fn relay_only_follower_route_refusal_chirho(")
        .nth(1)
        .expect("relay-only route refusal");
    let guard_chirho = guard_tail_chirho
        .split("pub(super) struct RelayedRequestMarkerChirho")
        .next()
        .expect("bounded relay-only route refusal body");
    assert!(
        guard_chirho.contains(
            "path_chirho == CREDITS_SPEND_PATH_CHIRHO"
        ) && guard_chirho.contains(
            "RelayRefusalIdentityChirho::RelayMutationFamilyUnconvertedChirho"
        ),
        "the route guard must allow only the exact converted path and default every other path to the named unconverted refusal"
    );
    assert!(
        !guard_chirho.contains("starts_with(") && !guard_chirho.contains("contains("),
        "the relay-only allowlist must not widen by prefix or substring"
    );
}
