// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P4 election-plane no-mint guard: the writer-election crates observe/elect (shadow), they must NEVER
//! mint a fence or commit a head. The local fence lock stays the sole minter in shadow; the elected
//! leader gains mint authority only at the separate, hard-gated P5 cutover — which is not in these
//! crates. Enforced at the crate boundary, not just by review.

use super::super::*;
use std::collections::BTreeSet;
use syn::visit::Visit;

#[path = "elector_no_mint_guard_tests_chirho/callable_tables_chirho.rs"]
mod callable_tables_chirho;
use callable_tables_chirho::*;

/// The writer-election crates. Their shared consistency-group coordinate comes from
/// `cairn-core-chirho`; their production dependency closure must never reach writer-head at all,
/// and their source must never CALL a fence-mint or head-commit.
const ELECTOR_CRATES_CHIRHO: &[&str] = &[
    "crates/support-chirho/cairn-writer-elector-chirho",
    "crates/stores-chirho/cairn-writer-elector-http-chirho",
];

/// Foundation symbols that remain unwired after H3 activation. Any caller outside the defining
/// module is an authority-boundary change and must deliberately replace this guard.
const UNWIRED_AUTHORITY_FOUNDATION_SYMBOLS_CHIRHO: &[(&str, &str)] = &[
    (
        "issue_elected_writer_fence_chirho",
        "crates/support-chirho/cairn-writer-head-chirho/src/writer_head_chirho.rs",
    ),
    (
        "issue_elected_writer_fence_for_root_chirho",
        "crates/support-chirho/cairn-writer-head-chirho/src/writer_head_chirho.rs",
    ),
    (
        "ElectedLedgerAuthorityBridgeChirho",
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/elected_authority_chirho.rs",
    ),
];

/// Globally unique authority identifiers the election plane must never reference — any fence mint,
/// head commit, ref mutation, or authority append. Parsed identifiers ignore comments and prose,
/// while direct calls, same-source imports/aliases, function values, and macro tokens still expose
/// the original authority name. Alias chains exported by another crate remain a dependency-surface
/// concern until the mutable writer-head API is split from the shared model types.
///
/// The elector depends on the FULL public surface of `cairn-writer-head-chirho`, so this must deny every
/// reachable mint/commit entrypoint of that crate (the fence primitives AND the head-transition / gate1
/// scopes that wrap them), not only the leaf primitives — otherwise an author (human or AI, cairn's whole
/// thesis) could mint through a higher-level scope while the guard stayed green. (A future hardening is to
/// DERIVE this list from the mutable-head inventory rather than hand-maintaining it.)
const FORBIDDEN_AUTHORITY_IDENTIFIERS_CHIRHO: &[&str] = &[
    // Fixes a root's control-plane law (C2.1 1a-ii); only the lineage-law signing path may call it.
    "publish_control_plane_law_marker_chirho",
    // The root handle's write scope and its signing (C2.1 1b-1a): the lock that orders the marker, and
    // the signature that may publish it.
    "with_control_plane_write_chirho",
    "sign_control_plane_record_chirho",
    "issue_elected_writer_fence_chirho",
    "issue_elected_writer_fence_for_root_chirho",
    "issue_writer_fence_chirho",
    "issue_writer_fence_for_root_chirho",
    "prepare_reused_or_issued_elected_writer_fence_chirho",
    "with_issued_writer_fence_chirho",
    "with_issued_writer_fence_for_root_chirho",
    "with_reused_or_issued_elected_writer_fence_chirho",
    "with_elected_head_transition_scope_chirho",
    "with_elected_run_admission_scope_chirho",
    "dispatch_head_transition_chirho",
    "complete_head_transition_chirho",
    "commit_head_chirho",
    "with_head_commit_chirho",
    // Higher-level scopes that mint a fence and/or commit a head transition (found reachable by the
    // P4/P5 adversarial audit — the elector could call these directly and the guard must catch them).
    "with_head_transition_scope_chirho",
    "with_gate1_authority_scope_chirho",
    "recover_head_transition_chirho",
    "complete_head_transition_unlocked_chirho",
    "pending_head_transition_index_unlocked_chirho",
    "set_branch_chirho",
    "rollback_chirho",
    "remove_branch_chirho",
    "compare_and_set_branch_chirho",
    "commit_head_with_transition_receipt_chirho",
    "append_gate1_authority_record_chirho",
    "append_gate1_authority_record_unlocked_chirho",
    "recover_gate1_authority_head_chirho",
    "recover_gate1_authority_head_unlocked_chirho",
    "reconcile_gate1_authority_prefix_unlocked_chirho",
    "reconcile_gate1_authority_current_family_tail_unlocked_chirho",
    "repair_gate1_authority_torn_tail_chirho",
    "repair_gate1_authority_torn_tail_unlocked_chirho",
    "bind_resident_writer_chirho",
    "open_exact_chirho",
    "open_resident_writer_chirho",
    "open_resident_writer_in_custody_chirho",
    "reserve_resident_writer_chirho",
    "reserve_resident_writer_in_custody_chirho",
    "save_refs_chirho",
];

fn record_forbidden_authority_identifier_chirho(
    identifier_chirho: &str,
    found_chirho: &mut BTreeSet<String>,
) {
    let normalized_chirho = identifier_chirho
        .strip_prefix("r#")
        .unwrap_or(identifier_chirho);
    if FORBIDDEN_AUTHORITY_IDENTIFIERS_CHIRHO.contains(&normalized_chirho) {
        found_chirho.insert(normalized_chirho.to_string());
    }
}

fn record_forbidden_macro_tokens_chirho(
    tokens_chirho: proc_macro2::TokenStream,
    found_chirho: &mut BTreeSet<String>,
) {
    for token_chirho in tokens_chirho {
        match token_chirho {
            proc_macro2::TokenTree::Ident(identifier_chirho) => {
                record_forbidden_authority_identifier_chirho(
                    &identifier_chirho.to_string(),
                    found_chirho,
                );
            }
            proc_macro2::TokenTree::Group(group_chirho) => {
                record_forbidden_macro_tokens_chirho(group_chirho.stream(), found_chirho);
            }
            _ => {}
        }
    }
}

#[derive(Default)]
struct AuthorityReferenceVisitorChirho {
    found_chirho: BTreeSet<String>,
}

fn item_attributes_chirho(item_chirho: &syn::Item) -> &[syn::Attribute] {
    match item_chirho {
        syn::Item::Const(item_chirho) => &item_chirho.attrs,
        syn::Item::Enum(item_chirho) => &item_chirho.attrs,
        syn::Item::ExternCrate(item_chirho) => &item_chirho.attrs,
        syn::Item::Fn(item_chirho) => &item_chirho.attrs,
        syn::Item::ForeignMod(item_chirho) => &item_chirho.attrs,
        syn::Item::Impl(item_chirho) => &item_chirho.attrs,
        syn::Item::Macro(item_chirho) => &item_chirho.attrs,
        syn::Item::Mod(item_chirho) => &item_chirho.attrs,
        syn::Item::Static(item_chirho) => &item_chirho.attrs,
        syn::Item::Struct(item_chirho) => &item_chirho.attrs,
        syn::Item::Trait(item_chirho) => &item_chirho.attrs,
        syn::Item::TraitAlias(item_chirho) => &item_chirho.attrs,
        syn::Item::Type(item_chirho) => &item_chirho.attrs,
        syn::Item::Union(item_chirho) => &item_chirho.attrs,
        syn::Item::Use(item_chirho) => &item_chirho.attrs,
        syn::Item::Verbatim(_) | _ => &[],
    }
}

impl<'ast_chirho> Visit<'ast_chirho> for AuthorityReferenceVisitorChirho {
    fn visit_item(&mut self, item_chirho: &'ast_chirho syn::Item) {
        if has_exact_cfg_test_attribute_chirho(item_attributes_chirho(item_chirho)) {
            return;
        }
        syn::visit::visit_item(self, item_chirho);
    }

    fn visit_attribute(&mut self, attribute_chirho: &'ast_chirho syn::Attribute) {
        for segment_chirho in &attribute_chirho.path().segments {
            record_forbidden_authority_identifier_chirho(
                &segment_chirho.ident.to_string(),
                &mut self.found_chirho,
            );
        }
        match &attribute_chirho.meta {
            syn::Meta::List(list_chirho) => record_forbidden_macro_tokens_chirho(
                list_chirho.tokens.clone(),
                &mut self.found_chirho,
            ),
            syn::Meta::NameValue(value_chirho) => self.visit_expr(&value_chirho.value),
            syn::Meta::Path(_) => {}
        }
    }

    fn visit_ident(&mut self, identifier_chirho: &'ast_chirho proc_macro2::Ident) {
        record_forbidden_authority_identifier_chirho(
            &identifier_chirho.to_string(),
            &mut self.found_chirho,
        );
    }

    fn visit_macro(&mut self, macro_chirho: &'ast_chirho syn::Macro) {
        for segment_chirho in &macro_chirho.path.segments {
            record_forbidden_authority_identifier_chirho(
                &segment_chirho.ident.to_string(),
                &mut self.found_chirho,
            );
        }
        record_forbidden_macro_tokens_chirho(macro_chirho.tokens.clone(), &mut self.found_chirho);
        syn::visit::visit_macro(self, macro_chirho);
    }
}

fn forbidden_authority_references_chirho(
    source_chirho: &str,
) -> Result<BTreeSet<String>, syn::Error> {
    let parsed_chirho = syn::parse_file(source_chirho)?;
    let mut visitor_chirho = AuthorityReferenceVisitorChirho::default();
    visitor_chirho.visit_file(&parsed_chirho);
    Ok(visitor_chirho.found_chirho)
}

struct ExactIdentifierPresenceVisitorChirho<'target_chirho> {
    target_chirho: &'target_chirho str,
    found_chirho: bool,
}

struct OptionalPathPredicateVisitorChirho<'path_chirho> {
    relative_path_chirho: &'path_chirho str,
    calls_chirho: Vec<String>,
}

fn method_receiver_coordinate_chirho(expression_chirho: &syn::Expr) -> String {
    match expression_chirho {
        syn::Expr::Path(path_chirho) if path_chirho.path.segments.len() == 1 => {
            path_chirho.path.segments[0].ident.to_string()
        }
        syn::Expr::MethodCall(call_chirho) => format!(
            "{}.{}()",
            method_receiver_coordinate_chirho(&call_chirho.receiver),
            call_chirho.method
        ),
        _ => "unclassified-receiver-chirho".to_owned(),
    }
}

impl<'ast_chirho> Visit<'ast_chirho> for OptionalPathPredicateVisitorChirho<'_> {
    fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
        if ["exists", "is_dir", "is_file"].contains(&call_chirho.method.to_string().as_str()) {
            self.calls_chirho.push(format!(
                "{}:{}:{}.{}()",
                self.relative_path_chirho,
                call_chirho.method,
                method_receiver_coordinate_chirho(&call_chirho.receiver),
                call_chirho.method
            ));
        }
        syn::visit::visit_expr_method_call(self, call_chirho);
    }
}

impl<'ast_chirho> Visit<'ast_chirho> for ExactIdentifierPresenceVisitorChirho<'_> {
    fn visit_ident(&mut self, identifier_chirho: &'ast_chirho proc_macro2::Ident) {
        if identifier_chirho == self.target_chirho {
            self.found_chirho = true;
        }
    }
}

fn production_identifier_reference_paths_chirho(target_chirho: &str) -> BTreeSet<String> {
    workspace_production_rs_files_chirho()
        .into_iter()
        .filter_map(|path_chirho| {
            let raw_chirho = std::fs::read_to_string(&path_chirho).unwrap();
            let production_chirho = production_text_chirho(&raw_chirho);
            let syntax_chirho = syn::parse_file(&production_chirho).unwrap_or_else(|error_chirho| {
                panic!(
                    "production canary consumer inventory must fail closed on unparseable {}: {error_chirho}",
                    workspace_relative_chirho(&path_chirho)
                )
            });
            let mut visitor_chirho = ExactIdentifierPresenceVisitorChirho {
                target_chirho,
                found_chirho: false,
            };
            visitor_chirho.visit_file(&syntax_chirho);
            visitor_chirho
                .found_chirho
                .then(|| workspace_relative_chirho(&path_chirho))
        })
        .collect()
}

fn public_use_markers_chirho(
    tree_chirho: &syn::UseTree,
    prefix_chirho: &mut Vec<String>,
    markers_chirho: &mut BTreeSet<String>,
) {
    match tree_chirho {
        syn::UseTree::Path(path_chirho) => {
            prefix_chirho.push(path_chirho.ident.to_string());
            public_use_markers_chirho(&path_chirho.tree, prefix_chirho, markers_chirho);
            prefix_chirho.pop();
        }
        syn::UseTree::Name(name_chirho) => {
            let mut coordinate_chirho = prefix_chirho.clone();
            coordinate_chirho.push(name_chirho.ident.to_string());
            markers_chirho.insert(format!("pub-use:{}", coordinate_chirho.join("::")));
        }
        syn::UseTree::Rename(rename_chirho) => {
            let mut coordinate_chirho = prefix_chirho.clone();
            coordinate_chirho.push(rename_chirho.ident.to_string());
            markers_chirho.insert(format!(
                "pub-use:{}=>{}",
                coordinate_chirho.join("::"),
                rename_chirho.rename
            ));
        }
        syn::UseTree::Glob(_) => {
            markers_chirho.insert(format!("pub-use:{}::*", prefix_chirho.join("::")));
        }
        syn::UseTree::Group(group_chirho) => {
            for item_chirho in &group_chirho.items {
                public_use_markers_chirho(item_chirho, prefix_chirho, markers_chirho);
            }
        }
    }
}

fn qualified_coordinate_chirho(prefix_chirho: &[String], leaf_chirho: &str) -> String {
    if prefix_chirho.is_empty() {
        leaf_chirho.to_string()
    } else {
        format!("{}::{leaf_chirho}", prefix_chirho.join("::"))
    }
}

fn implementation_type_name_chirho(type_chirho: &syn::Type) -> Option<String> {
    let syn::Type::Path(type_chirho) = type_chirho else {
        return None;
    };
    type_chirho
        .path
        .segments
        .last()
        .map(|segment_chirho| segment_chirho.ident.to_string())
}

#[derive(Default)]
struct CallableTypeVisitorChirho {
    found_chirho: bool,
}

impl<'ast_chirho> Visit<'ast_chirho> for CallableTypeVisitorChirho {
    fn visit_type_bare_fn(&mut self, _type_chirho: &'ast_chirho syn::TypeBareFn) {
        self.found_chirho = true;
    }

    fn visit_path_segment(&mut self, segment_chirho: &'ast_chirho syn::PathSegment) {
        if matches!(
            segment_chirho.ident.to_string().as_str(),
            "Fn" | "FnMut" | "FnOnce"
        ) {
            self.found_chirho = true;
        }
        syn::visit::visit_path_segment(self, segment_chirho);
    }
}

fn type_is_callable_chirho(type_chirho: &syn::Type) -> bool {
    let mut visitor_chirho = CallableTypeVisitorChirho::default();
    visitor_chirho.visit_type(type_chirho);
    visitor_chirho.found_chirho
}

fn record_callable_fields_chirho(
    fields_chirho: &syn::Fields,
    owner_chirho: &str,
    public_owner_fields_chirho: bool,
    marker_chirho: &str,
    prefix_chirho: &[String],
    callables_chirho: &mut BTreeSet<String>,
) {
    for (index_chirho, field_chirho) in fields_chirho.iter().enumerate() {
        if !type_is_callable_chirho(&field_chirho.ty)
            || (!public_owner_fields_chirho
                && !matches!(field_chirho.vis, syn::Visibility::Public(_)))
        {
            continue;
        }
        let field_name_chirho = field_chirho
            .ident
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| index_chirho.to_string());
        callables_chirho.insert(format!(
            "{marker_chirho}:{}",
            qualified_coordinate_chirho(
                prefix_chirho,
                &format!("{owner_chirho}::{field_name_chirho}"),
            )
        ));
    }
}

fn collect_public_module_callables_chirho(
    items_chirho: &[syn::Item],
    prefix_chirho: &mut Vec<String>,
    callables_chirho: &mut BTreeSet<String>,
) {
    for item_chirho in items_chirho {
        match item_chirho {
            syn::Item::Fn(function_chirho)
                if matches!(function_chirho.vis, syn::Visibility::Public(_)) =>
            {
                callables_chirho.insert(qualified_coordinate_chirho(
                    prefix_chirho,
                    &function_chirho.sig.ident.to_string(),
                ));
            }
            syn::Item::Impl(implementation_chirho) => {
                let Some(type_name_chirho) =
                    implementation_type_name_chirho(&implementation_chirho.self_ty)
                else {
                    callables_chirho.insert(qualified_coordinate_chirho(
                        prefix_chirho,
                        "unresolved-public-impl-chirho",
                    ));
                    continue;
                };
                for implementation_item_chirho in &implementation_chirho.items {
                    match implementation_item_chirho {
                        syn::ImplItem::Fn(method_chirho)
                            if implementation_chirho.trait_.is_some()
                                || matches!(method_chirho.vis, syn::Visibility::Public(_)) =>
                        {
                            callables_chirho.insert(qualified_coordinate_chirho(
                                prefix_chirho,
                                &format!("{type_name_chirho}::{}", method_chirho.sig.ident),
                            ));
                        }
                        syn::ImplItem::Const(constant_chirho)
                            if type_is_callable_chirho(&constant_chirho.ty)
                                && (implementation_chirho.trait_.is_some()
                                    || matches!(
                                        constant_chirho.vis,
                                        syn::Visibility::Public(_)
                                    )) =>
                        {
                            callables_chirho.insert(format!(
                                "const-fn:{}",
                                qualified_coordinate_chirho(
                                    prefix_chirho,
                                    &format!("{type_name_chirho}::{}", constant_chirho.ident),
                                )
                            ));
                        }
                        _ => {}
                    }
                }
            }
            syn::Item::Trait(trait_chirho)
                if matches!(trait_chirho.vis, syn::Visibility::Public(_)) =>
            {
                for trait_item_chirho in &trait_chirho.items {
                    match trait_item_chirho {
                        syn::TraitItem::Fn(method_chirho) => {
                            callables_chirho.insert(qualified_coordinate_chirho(
                                prefix_chirho,
                                &format!("{}::{}", trait_chirho.ident, method_chirho.sig.ident),
                            ));
                        }
                        syn::TraitItem::Const(constant_chirho)
                            if type_is_callable_chirho(&constant_chirho.ty) =>
                        {
                            callables_chirho.insert(format!(
                                "const-fn:{}",
                                qualified_coordinate_chirho(
                                    prefix_chirho,
                                    &format!("{}::{}", trait_chirho.ident, constant_chirho.ident),
                                )
                            ));
                        }
                        _ => {}
                    }
                }
            }
            syn::Item::Struct(struct_chirho)
                if matches!(struct_chirho.vis, syn::Visibility::Public(_)) =>
            {
                record_callable_fields_chirho(
                    &struct_chirho.fields,
                    &struct_chirho.ident.to_string(),
                    false,
                    "field-fn",
                    prefix_chirho,
                    callables_chirho,
                );
            }
            syn::Item::Enum(enum_chirho)
                if matches!(enum_chirho.vis, syn::Visibility::Public(_)) =>
            {
                for variant_chirho in &enum_chirho.variants {
                    record_callable_fields_chirho(
                        &variant_chirho.fields,
                        &format!("{}::{}", enum_chirho.ident, variant_chirho.ident),
                        true,
                        "variant-field-fn",
                        prefix_chirho,
                        callables_chirho,
                    );
                }
            }
            syn::Item::Union(union_chirho)
                if matches!(union_chirho.vis, syn::Visibility::Public(_)) =>
            {
                record_callable_fields_chirho(
                    &syn::Fields::Named(union_chirho.fields.clone()),
                    &union_chirho.ident.to_string(),
                    false,
                    "field-fn",
                    prefix_chirho,
                    callables_chirho,
                );
            }
            syn::Item::Const(constant_chirho)
                if matches!(constant_chirho.vis, syn::Visibility::Public(_))
                    && type_is_callable_chirho(&constant_chirho.ty) =>
            {
                callables_chirho.insert(format!(
                    "const-fn:{}",
                    qualified_coordinate_chirho(prefix_chirho, &constant_chirho.ident.to_string(),)
                ));
            }
            syn::Item::Static(static_chirho)
                if matches!(static_chirho.vis, syn::Visibility::Public(_))
                    && type_is_callable_chirho(&static_chirho.ty) =>
            {
                callables_chirho.insert(format!(
                    "static-fn:{}",
                    qualified_coordinate_chirho(prefix_chirho, &static_chirho.ident.to_string(),)
                ));
            }
            syn::Item::Use(use_chirho) if matches!(use_chirho.vis, syn::Visibility::Public(_)) => {
                let mut use_prefix_chirho = prefix_chirho.to_vec();
                public_use_markers_chirho(
                    &use_chirho.tree,
                    &mut use_prefix_chirho,
                    callables_chirho,
                );
            }
            syn::Item::Mod(module_chirho)
                if matches!(module_chirho.vis, syn::Visibility::Public(_)) =>
            {
                let module_name_chirho = module_chirho.ident.to_string();
                callables_chirho.insert(format!(
                    "public-module:{}",
                    qualified_coordinate_chirho(prefix_chirho, &module_name_chirho)
                ));
                if let Some((_brace_chirho, nested_items_chirho)) = &module_chirho.content {
                    prefix_chirho.push(module_name_chirho);
                    collect_public_module_callables_chirho(
                        nested_items_chirho,
                        prefix_chirho,
                        callables_chirho,
                    );
                    prefix_chirho.pop();
                }
            }
            syn::Item::Macro(macro_chirho)
                if macro_chirho
                    .attrs
                    .iter()
                    .any(|attribute_chirho| attribute_chirho.path().is_ident("macro_export")) =>
            {
                callables_chirho.insert(format!(
                    "macro:{}",
                    macro_chirho
                        .ident
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "anonymous-chirho".to_string())
                ));
            }
            syn::Item::ForeignMod(foreign_chirho) => {
                for foreign_item_chirho in &foreign_chirho.items {
                    match foreign_item_chirho {
                        syn::ForeignItem::Fn(function_chirho)
                            if matches!(function_chirho.vis, syn::Visibility::Public(_)) =>
                        {
                            callables_chirho.insert(format!(
                                "foreign-fn:{}",
                                qualified_coordinate_chirho(
                                    prefix_chirho,
                                    &function_chirho.sig.ident.to_string(),
                                )
                            ));
                        }
                        syn::ForeignItem::Static(static_chirho)
                            if matches!(static_chirho.vis, syn::Visibility::Public(_))
                                && type_is_callable_chirho(&static_chirho.ty) =>
                        {
                            callables_chirho.insert(format!(
                                "foreign-static-fn:{}",
                                qualified_coordinate_chirho(
                                    prefix_chirho,
                                    &static_chirho.ident.to_string(),
                                )
                            ));
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

pub(super) fn public_module_callables_chirho(source_chirho: &str) -> BTreeSet<String> {
    let parsed_chirho =
        syn::parse_file(source_chirho).expect("authority module source must remain parseable Rust");
    let mut callables_chirho = BTreeSet::new();
    collect_public_module_callables_chirho(
        &parsed_chirho.items,
        &mut Vec::new(),
        &mut callables_chirho,
    );
    callables_chirho
}

#[test]
fn writer_election_source_never_mints_a_fence_or_commits_a_head_chirho() {
    let production_files_chirho = workspace_production_rs_files_chirho();
    let manifests_chirho = production_files_chirho
        .iter()
        .filter_map(|path_chirho| nearest_package_manifest_chirho(path_chirho))
        .collect::<BTreeSet<_>>();
    let discovered_crates_chirho = manifests_chirho
        .into_iter()
        .filter_map(|manifest_chirho| {
            let source_chirho = std::fs::read_to_string(&manifest_chirho)
                .expect("workspace package manifest must remain readable");
            let manifest_value_chirho = source_chirho
                .parse::<toml::Value>()
                .expect("workspace package manifest must remain parseable TOML");
            let package_name_chirho = manifest_value_chirho
                .get("package")?
                .get("name")?
                .as_str()?;
            if !package_name_chirho.starts_with("cairn-writer-elector") {
                return None;
            }
            Some(workspace_relative_chirho(manifest_chirho.parent()?))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        discovered_crates_chirho,
        ELECTOR_CRATES_CHIRHO
            .iter()
            .map(|crate_dir_chirho| (*crate_dir_chirho).to_string())
            .collect(),
        "writer-election crate inventory drifted; classify every new elector package before its source can be trusted"
    );

    let elector_files_chirho: Vec<_> = production_files_chirho
        .into_iter()
        .filter(|path_chirho| {
            let rel_chirho = workspace_relative_chirho(path_chirho);
            ELECTOR_CRATES_CHIRHO
                .iter()
                .any(|crate_dir_chirho| rel_chirho.starts_with(&format!("{crate_dir_chirho}/src")))
        })
        .collect();
    assert!(
        !elector_files_chirho.is_empty(),
        "the writer-election no-mint guard found no elector source files — path drift?"
    );
    for path_chirho in elector_files_chirho {
        let raw_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let references_chirho = forbidden_authority_references_chirho(&raw_chirho).unwrap_or_else(
            |error_chirho| {
                panic!(
                    "writer-election production source must remain parseable Rust: {}: {error_chirho}",
                    workspace_relative_chirho(&path_chirho)
                )
            },
        );
        assert!(
            references_chirho.is_empty(),
            "{} references forbidden fence-mint/commit authority identifiers {references_chirho:?}: the election plane must not mint in shadow",
            workspace_relative_chirho(&path_chirho)
        );
    }
}

#[test]
fn remaining_authority_foundation_has_no_production_caller_chirho() {
    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let raw_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let source_chirho = production_text_chirho(&raw_chirho);
        for &(symbol_chirho, owner_chirho) in UNWIRED_AUTHORITY_FOUNDATION_SYMBOLS_CHIRHO {
            if relative_chirho == owner_chirho {
                continue;
            }
            assert!(
                !source_chirho.contains(symbol_chirho),
                "{relative_chirho} references unwired authority foundation {symbol_chirho}; production use requires a separately reviewed bridge and guard replacement"
            );
        }
    }
}

#[test]
fn h3_raw_shadow_canary_store_has_exact_production_owners_chirho() {
    let reference_paths_chirho =
        production_identifier_reference_paths_chirho("ShadowCanaryEvidenceStoreChirho");
    assert_eq!(
        reference_paths_chirho,
        BTreeSet::from([
            "crates/ledger-chirho/cairn-ledger-regenesis-chirho/src/money_stage_chirho.rs"
                .to_owned(),
            "crates/support-chirho/cairn-writer-elector-chirho/src/shadow_canary_chirho.rs"
                .to_owned(),
            "crates/support-chirho/cairn-writer-elector-chirho/src/shadow_canary_generation_chirho.rs"
                .to_owned(),
        ]),
        "raw H3 canary evidence must remain confined to its store, the generation-aware wrapper, and the generation-zero offline activation writer"
    );
}

#[test]
fn h3_generation_aware_canary_store_has_exact_production_consumers_chirho() {
    let reference_paths_chirho =
        production_identifier_reference_paths_chirho("ShadowCanaryGenerationStoreChirho");
    assert_eq!(
        reference_paths_chirho,
        BTreeSet::from([
            "crates/authoring-chirho/cairn-tenant-placement-author-chirho/src/authoring_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/held_coordinator_chirho/losing_journal_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/resident_mutation_chirho/envelope_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho/command_dispatch_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho/recovery_adoption_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/shadow_canary_report_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-regenesis-chirho/src/money_stage_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-regenesis-chirho/src/publication_verify_chirho.rs"
                .to_owned(),
            "crates/support-chirho/cairn-writer-elector-chirho/src/shadow_canary_generation_chirho.rs"
                .to_owned(),
        ]),
        "every production canary consumer must resolve through the generation-aware store; a new consumer requires an explicit generation-semantics review"
    );
}

#[test]
fn configured_shadow_canary_report_production_reference_census_is_explicit_chirho() {
    let report_references_chirho = production_identifier_reference_paths_chirho(
        "configured_shadow_canary_report_read_only_chirho",
    );
    assert_eq!(
        report_references_chirho,
        BTreeSet::from([
            "crates/cairn-cli-chirho/src/cli_helpers_chirho/reporting_chirho/shadow_canary_cli_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/lib.rs".to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/shadow_canary_report_chirho.rs"
                .to_owned(),
        ]),
        "the configured canary report production reference population changed; this is a textual census and any new reference requires authority review"
    );
    let proof_export_references_chirho = production_identifier_reference_paths_chirho(
        "export_current_window_proof_read_only_chirho",
    );
    assert_eq!(
        proof_export_references_chirho,
        BTreeSet::from([
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/shadow_canary_report_chirho.rs"
                .to_owned(),
            "crates/support-chirho/cairn-writer-elector-chirho/src/shadow_canary_generation_chirho.rs"
                .to_owned(),
        ]),
        "the read-only canary proof export production reference population changed; this census does not itself prove caller behavior"
    );
}

fn shadow_canary_production_reference_surface_chirho() -> BTreeSet<String> {
    [
        "SignedShadowCanaryActivationAnchorChirho",
        "ShadowCanaryEvidenceStoreChirho",
        "ShadowCanaryGenerationStoreChirho",
        "configured_shadow_canary_report_read_only_chirho",
        "export_current_window_proof_read_only_chirho",
    ]
    .into_iter()
    .flat_map(production_identifier_reference_paths_chirho)
    .collect()
}

#[test]
fn optional_shadow_canary_path_predicate_census_is_metadata_backed_chirho() {
    let root_chirho = workspace_root_chirho();
    let mut calls_chirho = Vec::new();
    for relative_chirho in shadow_canary_production_reference_surface_chirho() {
        let raw_source_chirho = std::fs::read_to_string(root_chirho.join(&relative_chirho))
            .expect("read shadow canary optional-path source");
        let source_chirho = production_text_chirho(&raw_source_chirho);
        let syntax_chirho = syn::parse_file(&source_chirho)
            .expect("parse shadow canary optional-path production source");
        let mut visitor_chirho = OptionalPathPredicateVisitorChirho {
            relative_path_chirho: &relative_chirho,
            calls_chirho: Vec::new(),
        };
        visitor_chirho.visit_file(&syntax_chirho);
        calls_chirho.extend(visitor_chirho.calls_chirho);
    }
    calls_chirho.sort();
    assert_eq!(
        calls_chirho,
        vec![
            "crates/authoring-chirho/cairn-tenant-placement-author-chirho/src/authoring_chirho.rs:is_file:metadata_chirho.is_file()".to_owned(),
            "crates/cairn-cli-chirho/src/cli_helpers_chirho/reporting_chirho/shadow_canary_cli_chirho.rs:is_file:metadata_chirho.file_type().is_file()".to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/shadow_canary_report_chirho.rs:is_dir:metadata_chirho.file_type().is_dir()".to_owned(),
            "crates/support-chirho/cairn-writer-elector-chirho/src/shadow_canary_activation_anchor_chirho.rs:is_file:final_metadata_chirho.file_type().is_file()".to_owned(),
            "crates/support-chirho/cairn-writer-elector-chirho/src/shadow_canary_activation_anchor_chirho.rs:is_file:opened_metadata_chirho.is_file()".to_owned(),
            "crates/support-chirho/cairn-writer-elector-chirho/src/shadow_canary_activation_anchor_chirho.rs:is_file:path_metadata_chirho.file_type().is_file()".to_owned(),
            "crates/support-chirho/cairn-writer-elector-chirho/src/shadow_canary_chirho.rs:is_dir:metadata_chirho.file_type().is_dir()".to_owned(),
            "crates/support-chirho/cairn-writer-elector-chirho/src/shadow_canary_chirho.rs:is_file:final_metadata_chirho.file_type().is_file()".to_owned(),
            "crates/support-chirho/cairn-writer-elector-chirho/src/shadow_canary_chirho.rs:is_file:opened_metadata_chirho.is_file()".to_owned(),
            "crates/support-chirho/cairn-writer-elector-chirho/src/shadow_canary_chirho.rs:is_file:path_metadata_chirho.file_type().is_file()".to_owned(),
            "crates/support-chirho/cairn-writer-elector-chirho/src/shadow_canary_generation_chirho.rs:is_file:path_metadata_chirho.file_type().is_file()".to_owned(),
        ],
        "the canary exists/is-dir/is-file predicate population changed; only kind checks on metadata acquired through explicit error handling are accepted"
    );
}

#[test]
fn h3_generation_zero_cutover_consumers_use_the_central_window_chirho() {
    let reference_paths_chirho =
        production_identifier_reference_paths_chirho("require_generation_zero_window_chirho");
    assert_eq!(
        reference_paths_chirho,
        BTreeSet::from([
            "crates/authoring-chirho/cairn-tenant-placement-author-chirho/src/authoring_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-regenesis-chirho/src/money_stage_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-regenesis-chirho/src/publication_verify_chirho.rs"
                .to_owned(),
            "crates/support-chirho/cairn-writer-elector-chirho/src/shadow_canary_generation_chirho.rs"
                .to_owned(),
        ]),
        "generation-zero cutover consumers must positively route through the central generation check; a new canary consumer without this call is not lifetime cutover evidence"
    );
}

#[test]
fn mutable_authority_public_surface_stays_role_classified_chirho() {
    let root_chirho = workspace_root_chirho();
    for (path_chirho, expected_chirho) in [
        (
            "crates/support-chirho/cairn-writer-head-chirho/src/writer_head_chirho.rs",
            WRITER_HEAD_PUBLIC_CALLABLES_CHIRHO,
        ),
        (
            "crates/support-chirho/cairn-writer-head-chirho/src/head_transition_chirho.rs",
            HEAD_TRANSITION_PUBLIC_CALLABLES_CHIRHO,
        ),
        (
            "crates/support-chirho/cairn-writer-head-chirho/src/head_transition_authority_chirho.rs",
            HEAD_TRANSITION_AUTHORITY_PUBLIC_CALLABLES_CHIRHO,
        ),
        (
            "crates/support-chirho/cairn-writer-head-chirho/src/resident_writer_chirho.rs",
            RESIDENT_WRITER_PUBLIC_CALLABLES_CHIRHO,
        ),
        (
            "crates/support-chirho/cairn-writer-head-chirho/src/control_plane_evidence_chirho.rs",
            CONTROL_PLANE_EVIDENCE_PUBLIC_CALLABLES_CHIRHO,
        ),
        (
            "crates/support-chirho/cairn-writer-head-chirho/src/control_plane_root_chirho.rs",
            CONTROL_PLANE_ROOT_PUBLIC_CALLABLES_CHIRHO,
        ),
        (
            "crates/services-chirho/cairn-gate1-authority-log-chirho/src/authority_log_chirho.rs",
            GATE1_AUTHORITY_LOG_PUBLIC_CALLABLES_CHIRHO,
        ),
    ] {
        let source_chirho = std::fs::read_to_string(root_chirho.join(path_chirho)).unwrap();
        let actual_chirho = public_module_callables_chirho(&source_chirho);
        let expected_coordinates_chirho = expected_chirho
            .iter()
            .map(|(coordinate_chirho, _role_chirho)| (*coordinate_chirho).to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            expected_coordinates_chirho.len(),
            expected_chirho.len(),
            "duplicate authority coordinate in the role-classified allowlist for {path_chirho}"
        );
        assert_eq!(
            actual_chirho,
            expected_coordinates_chirho,
            "public authority surface drifted in {path_chirho}; classify every new function before the election guard trusts it"
        );
        for (coordinate_chirho, role_chirho) in expected_chirho {
            if *role_chirho != FORBIDDEN_AUTHORITY_ROLE_CHIRHO {
                continue;
            }
            let identifier_chirho = coordinate_chirho
                .rsplit_once("::")
                .map(|(_type_chirho, method_chirho)| method_chirho)
                .unwrap_or(coordinate_chirho);
            assert!(
                FORBIDDEN_AUTHORITY_IDENTIFIERS_CHIRHO.contains(&identifier_chirho),
                "forbidden public authority callable {coordinate_chirho} is absent from the election-plane denylist"
            );
        }
    }
}

#[test]
fn authority_crate_public_module_set_stays_bounded_chirho() {
    let root_chirho = workspace_root_chirho();
    for (path_chirho, expected_chirho) in [
        (
            "crates/support-chirho/cairn-writer-head-chirho/src/lib.rs",
            WRITER_HEAD_CRATE_PUBLIC_MODULES_CHIRHO,
        ),
        (
            "crates/services-chirho/cairn-gate1-authority-log-chirho/src/lib.rs",
            GATE1_AUTHORITY_CRATE_PUBLIC_MODULES_CHIRHO,
        ),
    ] {
        let source_chirho = std::fs::read_to_string(root_chirho.join(path_chirho)).unwrap();
        let actual_chirho = public_module_callables_chirho(&source_chirho);
        assert_eq!(
            actual_chirho,
            expected_chirho
                .iter()
                .map(|coordinate_chirho| (*coordinate_chirho).to_string())
                .collect(),
            "authority crate root drifted in {path_chirho}; inventory every new public module before the election guard trusts the crate"
        );
    }
}

#[test]
fn election_authority_reference_inventory_catches_real_alias_and_macro_forms_chirho() {
    let source_chirho = r#"
        use authority_log_chirho::{
            append_gate1_authority_record_chirho as append_record_chirho,
            append_gate1_authority_record_unlocked_chirho as append_unlocked_chirho,
        };

        #[delegate_chirho(issue_writer_fence_chirho)]
        fn retain_function_value_chirho() {
            let callback_chirho = append_record_chirho;
            delegate_chirho!((issue_writer_fence_for_root_chirho));
            writer_head_chirho::r#with_head_commit_chirho();
            authority_chirho.remove_branch_chirho();
            let saved_chirho = authority_chirho.save_refs_chirho;
            let unlocked_chirho = append_unlocked_chirho;
            let _ = callback_chirho;
            let _ = saved_chirho;
            let _ = unlocked_chirho;
        }

        #[cfg(test)]
        fn ignored_test_authority_chirho() {
            compare_and_set_branch_chirho();
        }
    "#;
    assert_eq!(
        forbidden_authority_references_chirho(source_chirho).unwrap(),
        BTreeSet::from([
            "append_gate1_authority_record_chirho".to_string(),
            "append_gate1_authority_record_unlocked_chirho".to_string(),
            "issue_writer_fence_chirho".to_string(),
            "issue_writer_fence_for_root_chirho".to_string(),
            "remove_branch_chirho".to_string(),
            "save_refs_chirho".to_string(),
            "with_head_commit_chirho".to_string(),
        ])
    );
}

#[test]
fn public_authority_inventory_catches_indirect_callable_exports_chirho() {
    let source_chirho = r#"
        pub trait AuthorityTraitChirho {
            fn mutate_chirho(&self);
        }

        pub struct AuthorityTypeChirho;

        pub struct AuthorityCallbacksChirho {
            pub callback_chirho: fn(),
        }

        pub enum AuthorityEventChirho {
            CallbackChirho { run_chirho: fn() },
        }

        pub union AuthorityUnionChirho {
            pub callback_chirho: fn(),
        }

        pub const MUTATE_CALLBACK_CHIRHO: fn() = mutate_chirho;

        impl AuthorityTraitChirho for AuthorityTypeChirho {
            fn mutate_chirho(&self) {}
        }

        pub use authority_chirho::{commit_chirho as commit_alias_chirho, nested_chirho::*};

        #[macro_export]
        macro_rules! mutate_macro_chirho {
            () => {};
        }

        pub mod nested_chirho {
            pub fn nested_mutate_chirho() {}
        }

        extern "C" {
            pub fn foreign_mutate_chirho();
            pub static FOREIGN_CALLBACK_CHIRHO: fn();
        }
    "#;
    assert_eq!(
        public_module_callables_chirho(source_chirho),
        BTreeSet::from([
            "AuthorityTraitChirho::mutate_chirho".to_string(),
            "AuthorityTypeChirho::mutate_chirho".to_string(),
            "const-fn:MUTATE_CALLBACK_CHIRHO".to_string(),
            "field-fn:AuthorityCallbacksChirho::callback_chirho".to_string(),
            "field-fn:AuthorityUnionChirho::callback_chirho".to_string(),
            "foreign-fn:foreign_mutate_chirho".to_string(),
            "foreign-static-fn:FOREIGN_CALLBACK_CHIRHO".to_string(),
            "macro:mutate_macro_chirho".to_string(),
            "nested_chirho::nested_mutate_chirho".to_string(),
            "pub-use:authority_chirho::commit_chirho=>commit_alias_chirho".to_string(),
            "pub-use:authority_chirho::nested_chirho::*".to_string(),
            "public-module:nested_chirho".to_string(),
            "variant-field-fn:AuthorityEventChirho::CallbackChirho::run_chirho".to_string(),
        ])
    );
}
