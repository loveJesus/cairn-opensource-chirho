// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Exact elected-fence helper and head-transition authority-port inventories.

use super::resident_signer_source_guard_tests_chirho::elected_fence_helper_inventory_chirho;
use super::*;

pub(super) const ELECTED_FENCE_HELPER_CHIRHO: &str =
    "with_reused_or_issued_elected_writer_fence_chirho";
const ELECTED_FENCE_HELPER_OWNER_CHIRHO: &str =
    "crates/support-chirho/cairn-writer-head-chirho/src/writer_head_chirho.rs";
const HEAD_TRANSITION_AUTHORITY_PORT_CHIRHO: &str = "HeadTransitionAuthorityPortChirho";

pub(super) fn is_exact_optional_arc_trait_chirho(
    type_chirho: &Type,
    expected_trait_chirho: &str,
) -> bool {
    let Type::Path(option_path_chirho) = type_chirho else {
        return false;
    };
    let Some(option_segment_chirho) = option_path_chirho.path.segments.last() else {
        return false;
    };
    if option_segment_chirho.ident != "Option" {
        return false;
    }
    let PathArguments::AngleBracketed(option_arguments_chirho) = &option_segment_chirho.arguments
    else {
        return false;
    };
    let [GenericArgument::Type(Type::Path(arc_path_chirho))] = option_arguments_chirho
        .args
        .iter()
        .collect::<Vec<_>>()
        .as_slice()
    else {
        return false;
    };
    let Some(arc_segment_chirho) = arc_path_chirho.path.segments.last() else {
        return false;
    };
    if arc_segment_chirho.ident != "Arc" {
        return false;
    }
    let PathArguments::AngleBracketed(arc_arguments_chirho) = &arc_segment_chirho.arguments else {
        return false;
    };
    let [GenericArgument::Type(Type::TraitObject(trait_object_chirho))] = arc_arguments_chirho
        .args
        .iter()
        .collect::<Vec<_>>()
        .as_slice()
    else {
        return false;
    };
    let [syn::TypeParamBound::Trait(trait_bound_chirho)] = trait_object_chirho
        .bounds
        .iter()
        .collect::<Vec<_>>()
        .as_slice()
    else {
        return false;
    };
    trait_bound_chirho
        .path
        .segments
        .last()
        .is_some_and(|segment_chirho| segment_chirho.ident == expected_trait_chirho)
}

#[test]
fn elected_fence_helper_has_one_definition_and_two_reviewed_production_bridges_chirho() {
    let production_files_chirho = workspace_production_rs_files_chirho();
    let mut definitions_chirho = BTreeSet::new();
    let mut references_chirho = BTreeSet::new();
    let mut identifier_builders_chirho = BTreeSet::new();
    for path_chirho in production_files_chirho {
        let raw_source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let source_chirho = production_text_chirho(&raw_source_chirho);
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        if source_chirho.contains("concat_idents!") || source_chirho.contains("paste!") {
            identifier_builders_chirho.insert(relative_chirho.clone());
        }
        if !source_chirho.contains(ELECTED_FENCE_HELPER_CHIRHO) {
            continue;
        }
        let (definition_count_chirho, reference_count_chirho) =
            elected_fence_helper_inventory_chirho(&source_chirho);
        if definition_count_chirho > 0 {
            definitions_chirho.insert((relative_chirho.clone(), definition_count_chirho));
        }
        if reference_count_chirho > 0 {
            references_chirho.insert((relative_chirho, reference_count_chirho));
        }
    }
    assert_eq!(
        definitions_chirho,
        BTreeSet::from([(ELECTED_FENCE_HELPER_OWNER_CHIRHO.to_owned(), 1)]),
        "the elected fence helper definition moved or duplicated"
    );
    assert_eq!(
        references_chirho,
        BTreeSet::from([(
            "crates/support-chirho/cairn-writer-head-chirho/src/head_transition_authority_chirho.rs"
                .to_owned(),
            2,
        ), (
            "crates/support-chirho/cairn-writer-head-chirho/src/run_admission_authority_chirho.rs".to_owned(),
            2,
        )]),
        "the elected fence helper may be imported and called only by the reviewed head and admission bridges"
    );
    assert!(
        identifier_builders_chirho.is_empty(),
        "production identifier-building macros could hide an elected-fence helper reference {identifier_builders_chirho:?}"
    );
}

fn collect_authority_port_aliases_chirho(
    tree_chirho: &UseTree,
    aliases_chirho: &mut BTreeSet<String>,
    expected_trait_chirho: &str,
) {
    match tree_chirho {
        UseTree::Path(path_chirho) => collect_authority_port_aliases_chirho(
            &path_chirho.tree,
            aliases_chirho,
            expected_trait_chirho,
        ),
        UseTree::Name(name_chirho) if name_chirho.ident == expected_trait_chirho => {
            aliases_chirho.insert(name_chirho.ident.to_string());
        }
        UseTree::Rename(rename_chirho) if rename_chirho.ident == expected_trait_chirho => {
            aliases_chirho.insert(rename_chirho.rename.to_string());
        }
        UseTree::Group(group_chirho) => {
            for item_chirho in &group_chirho.items {
                collect_authority_port_aliases_chirho(
                    item_chirho,
                    aliases_chirho,
                    expected_trait_chirho,
                );
            }
        }
        UseTree::Name(_) | UseTree::Rename(_) | UseTree::Glob(_) => {}
    }
}

#[derive(Default)]
struct AuthorityPortAliasVisitorChirho<'trait_chirho> {
    aliases_chirho: BTreeSet<String>,
    expected_trait_chirho: &'trait_chirho str,
}

impl<'ast_chirho> Visit<'ast_chirho> for AuthorityPortAliasVisitorChirho<'_> {
    fn visit_use_tree(&mut self, tree_chirho: &'ast_chirho UseTree) {
        collect_authority_port_aliases_chirho(
            tree_chirho,
            &mut self.aliases_chirho,
            self.expected_trait_chirho,
        );
        syn::visit::visit_use_tree(self, tree_chirho);
    }
}

struct AuthorityPortImplVisitorChirho<'a> {
    aliases_chirho: &'a BTreeSet<String>,
    implementers_chirho: BTreeSet<String>,
}

impl<'ast_chirho> Visit<'ast_chirho> for AuthorityPortImplVisitorChirho<'_> {
    fn visit_item_impl(&mut self, implementation_chirho: &'ast_chirho syn::ItemImpl) {
        if implementation_chirho
            .trait_
            .as_ref()
            .and_then(|(_bang_chirho, path_chirho, _for_chirho)| path_chirho.segments.last())
            .is_some_and(|segment_chirho| {
                self.aliases_chirho
                    .contains(&segment_chirho.ident.to_string())
            })
        {
            self.implementers_chirho
                .insert(canonical_type_path_chirho(&implementation_chirho.self_ty));
        }
        syn::visit::visit_item_impl(self, implementation_chirho);
    }
}

fn authority_port_implementers_chirho(
    source_chirho: &str,
    expected_trait_chirho: &str,
) -> BTreeSet<String> {
    let syntax_chirho =
        syn::parse_file(source_chirho).expect("authority-port source must remain parseable Rust");
    let mut alias_visitor_chirho = AuthorityPortAliasVisitorChirho {
        expected_trait_chirho,
        ..Default::default()
    };
    alias_visitor_chirho
        .aliases_chirho
        .insert(expected_trait_chirho.to_string());
    alias_visitor_chirho.visit_file(&syntax_chirho);
    let mut impl_visitor_chirho = AuthorityPortImplVisitorChirho {
        aliases_chirho: &alias_visitor_chirho.aliases_chirho,
        implementers_chirho: BTreeSet::new(),
    };
    impl_visitor_chirho.visit_file(&syntax_chirho);
    impl_visitor_chirho.implementers_chirho
}

#[test]
fn elected_head_transition_authority_port_has_one_reviewed_production_implementer_chirho() {
    let mut actual_chirho = BTreeSet::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let raw_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let source_chirho = production_text_chirho(&raw_chirho);
        for implementer_chirho in authority_port_implementers_chirho(
            &source_chirho,
            HEAD_TRANSITION_AUTHORITY_PORT_CHIRHO,
        ) {
            actual_chirho.insert((workspace_relative_chirho(&path_chirho), implementer_chirho));
        }
    }
    assert_eq!(
        actual_chirho,
        BTreeSet::from([(
            "crates/ledger-chirho/host-chirho/cairn-ledger-elected-head-transition-chirho/src/lib.rs"
                .to_owned(),
            "ElectedHeadTransitionAdapterChirho".to_owned(),
        )]),
        "only the reviewed ledger-host adapter may implement the elected head-transition authority port"
    );

    for source_chirho in [
        "impl HeadTransitionAuthorityPortChirho for DirectChirho {}",
        "impl<T> crate::HeadTransitionAuthorityPortChirho for GenericChirho<T> {}",
        "use crate::HeadTransitionAuthorityPortChirho as PortAliasChirho;\n\
         impl PortAliasChirho for AliasedChirho {}",
    ] {
        assert_eq!(
            authority_port_implementers_chirho(
                source_chirho,
                HEAD_TRANSITION_AUTHORITY_PORT_CHIRHO
            )
            .len(),
            1,
            "the implementation census must catch direct, qualified, generic, and aliased forms"
        );
    }
}

#[test]
fn elected_run_admission_port_has_one_host_owned_implementer_chirho() {
    let mut actual_chirho = BTreeSet::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let raw_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let source_chirho = production_text_chirho(&raw_chirho);
        for implementer_chirho in
            authority_port_implementers_chirho(&source_chirho, "RunAdmissionAuthorityPortChirho")
        {
            actual_chirho.insert((workspace_relative_chirho(&path_chirho), implementer_chirho));
        }
    }
    assert_eq!(actual_chirho, BTreeSet::from([(
        "crates/ledger-chirho/host-chirho/cairn-ledger-elected-head-transition-chirho/src/run_admission_chirho.rs".to_owned(),
        "ElectedHeadTransitionAdapterChirho".to_owned(),
    )]), "the app/runtime cannot implement its own elected run-admission issuer");
}

#[test]
fn run_admission_public_scope_surface_stays_classified_chirho() {
    let source_chirho = std::fs::read_to_string(workspace_root_chirho().join(
        "crates/support-chirho/cairn-writer-head-chirho/src/run_admission_authority_chirho.rs",
    ))
    .unwrap();
    let roles_chirho = [
        (
            "RunAdmissionCommitScopeChirho::validate_sink_chirho",
            "read-only-chirho",
        ),
        (
            "RunAdmissionScopeOutcomeChirho::observed_fence_chirho",
            "read-only-chirho",
        ),
        (
            "RunAdmissionScopeOutcomeChirho::into_result_chirho",
            "read-only-chirho",
        ),
        (
            "RunAdmissionCommitActionChirho::call_chirho",
            "callback-chirho",
        ),
        (
            "RunAdmissionAuthorityPortChirho::with_elected_run_admission_scope_chirho",
            "forbidden-to-elector-chirho",
        ),
        (
            "with_elected_run_admission_scope_chirho",
            "forbidden-to-elector-chirho",
        ),
    ];
    assert_eq!(
        super::super::elector_no_mint_guard_tests_chirho::public_module_callables_chirho(
            &source_chirho
        ),
        roles_chirho
            .into_iter()
            .map(|(name_chirho, _role_chirho)| name_chirho.to_owned())
            .collect(),
        "a new public scope callable requires explicit authority classification",
    );
}
