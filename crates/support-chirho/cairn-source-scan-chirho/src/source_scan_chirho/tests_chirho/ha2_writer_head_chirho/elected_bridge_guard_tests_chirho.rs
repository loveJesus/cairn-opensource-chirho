// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A6 non-flip boundary: one reviewed host bridge may call the elected fence helper, while no
//! in-workspace production composition may construct the bridge yet.

use super::super::*;
use std::collections::{BTreeMap, BTreeSet};
use syn::visit::Visit;
use syn::{GenericArgument, Item, PathArguments, Type, UseTree, Visibility};

#[path = "elected_bridge_guard_tests_chirho/signer_path_classifiers_chirho.rs"]
mod signer_path_classifiers_chirho;
use signer_path_classifiers_chirho::{
    classify_identity_key_name_chirho, classify_signer_path_chirho,
    classify_signer_target_path_chirho, collect_use_target_paths_chirho,
};

#[path = "elected_bridge_guard_tests_chirho/elected_authority_port_guard_tests_chirho.rs"]
mod elected_authority_port_guard_tests_chirho;
use elected_authority_port_guard_tests_chirho::{
    is_exact_optional_arc_trait_chirho, ELECTED_FENCE_HELPER_CHIRHO,
};
#[path = "elected_bridge_guard_tests_chirho/elected_bridge_module_guard_tests_chirho.rs"]
mod elected_bridge_module_guard_tests_chirho;
#[path = "elected_bridge_guard_tests_chirho/exact_target_reference_resolver_chirho.rs"]
mod exact_target_reference_resolver_chirho;
#[path = "elected_bridge_guard_tests_chirho/raw_ledger_journal_writer_guard_tests_chirho.rs"]
mod raw_ledger_journal_writer_guard_tests_chirho;
#[path = "elected_bridge_guard_tests_chirho/resident_activation_regression_guard_tests_chirho.rs"]
mod resident_activation_regression_guard_tests_chirho;
#[path = "elected_bridge_guard_tests_chirho/resident_birth_source_guard_tests_chirho.rs"]
mod resident_birth_source_guard_tests_chirho;
#[path = "elected_bridge_guard_tests_chirho/resident_signer_source_guard_tests_chirho.rs"]
mod resident_signer_source_guard_tests_chirho;
use exact_target_reference_resolver_chirho::{h3_target_inventory_chirho, H3_APPEND_TARGET_CHIRHO};
use resident_signer_source_guard_tests_chirho::{
    canonical_type_path_chirho, has_exact_cfg_test_chirho, visibility_is_crate_chirho,
    ModuleReferenceVisitorChirho,
};

#[test]
fn resident_ledger_bound_identity_is_production_private_with_reviewed_signers_chirho() {
    let root_chirho = workspace_root_chirho();
    let owner_path_chirho =
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_ledger_identity_chirho.rs";
    let host_lib_chirho =
        root_chirho.join("crates/ledger-chirho/cairn-ledger-host-chirho/src/lib.rs");
    let host_lib_source_chirho = std::fs::read_to_string(&host_lib_chirho).unwrap();
    let host_lib_ast_chirho = syn::parse_file(&host_lib_source_chirho).unwrap();
    let declarations_chirho = host_lib_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Mod(module_chirho)
                if module_chirho.ident == "resident_ledger_identity_chirho" =>
            {
                Some((
                    &module_chirho.vis,
                    has_exact_cfg_test_chirho(&module_chirho.attrs),
                ))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(declarations_chirho.len(), 1);
    assert!(matches!(declarations_chirho[0].0, Visibility::Inherited));
    assert!(!declarations_chirho[0].1);

    let production_files_chirho = workspace_production_rs_files_chirho();
    let production_paths_chirho = production_files_chirho
        .iter()
        .map(|path_chirho| workspace_relative_chirho(path_chirho))
        .collect::<BTreeSet<_>>();
    assert!(
        production_paths_chirho.contains(owner_path_chirho),
        "the signed Bound resident identity verifier must remain production compiled"
    );
    let identity_reference_paths_chirho = production_files_chirho
        .iter()
        .filter_map(|path_chirho| {
            let raw_chirho = std::fs::read_to_string(path_chirho).unwrap();
            let source_chirho = production_text_chirho(&raw_chirho);
            (source_chirho.contains("resident_ledger_identity_chirho")
                || source_chirho.contains("verify_bound_identity_chirho")
                || source_chirho.contains("ResidentLedgerCoordinateSourceChirho"))
            .then(|| workspace_relative_chirho(path_chirho))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        identity_reference_paths_chirho,
        BTreeSet::from([
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/lib.rs".to_owned(),
            owner_path_chirho.to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/birth_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/activation_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/held_coordinator_chirho/losing_journal_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/resident_mutation_chirho/authority_open_view_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/sink_term_lifecycle_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho.rs"
                .to_owned(),
        ]),
        "production resident identity references must remain confined to the private verifier, resident owner and its sink-cell refusal mapper, reviewed activation capsule, and held read-only verifier"
    );

    let owner_source_chirho = std::fs::read_to_string(root_chirho.join(owner_path_chirho)).unwrap();
    let owner_ast_chirho = syn::parse_file(&owner_source_chirho).unwrap();
    let identity_function_cfg_chirho = owner_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Fn(function_chirho)
                if [
                    "canonical_pending_identity_chirho",
                    "canonical_bound_identity_chirho",
                    "verify_pending_identity_chirho",
                    "verify_bound_identity_chirho",
                ]
                .contains(&function_chirho.sig.ident.to_string().as_str()) =>
            {
                Some((
                    function_chirho.sig.ident.to_string(),
                    has_exact_cfg_test_chirho(&function_chirho.attrs),
                ))
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        identity_function_cfg_chirho,
        BTreeSet::from([
            ("canonical_bound_identity_chirho".to_owned(), false),
            ("canonical_pending_identity_chirho".to_owned(), false),
            ("verify_bound_identity_chirho".to_owned(), false),
            ("verify_pending_identity_chirho".to_owned(), false),
        ]),
        "Pending and Bound identity encoding/verification must remain production-compiled for the sealed birth owner"
    );
    let mut key_calls_chirho = IdentityKeyCallVisitorChirho::default();
    key_calls_chirho.visit_file(&owner_ast_chirho);
    assert_eq!(
        key_calls_chirho.existing_calls_chirho,
        BTreeSet::from([
            "sign_with_existing_key_possession_chirho".to_owned(),
            "verify_with_pubkey_chirho".to_owned(),
        ]),
        "direct resident signer references must match the reviewed preactivation allowlist"
    );
    assert_eq!(
        key_calls_chirho.signer_targets_chirho,
        BTreeSet::from([
            "sign_with_existing_key_possession_chirho".to_owned(),
            "verify_with_pubkey_chirho".to_owned(),
        ]),
        "syntactic resident signer targets must match the reviewed preactivation allowlist"
    );
    assert_eq!(
        key_calls_chirho.direct_reference_pairs_chirho,
        BTreeSet::from([
            "canonical_bound_identity_for_coordinate_chirho->sign_with_existing_key_possession_chirho".to_owned(),
            "canonical_pending_identity_for_coordinate_with_schema_chirho->sign_with_existing_key_possession_chirho".to_owned(),
            "prove_current_signer_possession_chirho->sign_with_existing_key_possession_chirho".to_owned(),
            "verify_signature_chirho->verify_with_pubkey_chirho".to_owned(),
        ]),
        "resident identity direct reference pairs changed from the reviewed preactivation shape"
    );
    assert!(
        key_calls_chirho.unresolved_signer_targets_chirho.is_empty(),
        "resident identity gained an unresolved signer target {:?}",
        key_calls_chirho.unresolved_signer_targets_chirho
    );
    assert!(
        key_calls_chirho.creating_calls_chirho.is_empty(),
        "direct resident signer references include a reviewed key-creation spelling {:?}",
        key_calls_chirho.creating_calls_chirho
    );
    assert!(
        !owner_source_chirho.contains("macro_rules!")
            && !owner_source_chirho.contains("concat_idents!")
            && !owner_source_chirho.contains("paste!"),
        "identifier-building macros stay outside this syntactic signer inventory"
    );
    assert_resident_identity_types_are_non_debug_chirho(&owner_ast_chirho);
}

#[test]
fn production_resident_authority_surface_is_exact_sealed_and_receipt_source_bounded_chirho() {
    let root_chirho = workspace_root_chirho();
    let owner_path_chirho =
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho.rs";
    let birth_path_chirho =
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/birth_chirho.rs";
    let activation_path_chirho =
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/activation_chirho.rs";
    let append_path_chirho =
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/resident_mutation_chirho/authority_append_chirho.rs";
    let open_view_path_chirho =
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/resident_mutation_chirho/authority_open_view_chirho.rs";
    let host_lib_source_chirho = std::fs::read_to_string(
        root_chirho.join("crates/ledger-chirho/cairn-ledger-host-chirho/src/lib.rs"),
    )
    .unwrap();
    let host_lib_ast_chirho = syn::parse_file(&host_lib_source_chirho).unwrap();
    let module_declaration_chirho = host_lib_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Mod(module_chirho) if module_chirho.ident == "resident_authority_chirho" => {
                Some((
                    &module_chirho.vis,
                    has_exact_cfg_test_chirho(&module_chirho.attrs),
                ))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(module_declaration_chirho.len(), 1);
    assert!(matches!(
        module_declaration_chirho[0].0,
        Visibility::Inherited
    ));
    assert!(!module_declaration_chirho[0].1);

    let owner_source_chirho = std::fs::read_to_string(root_chirho.join(owner_path_chirho)).unwrap();
    let owner_ast_chirho = syn::parse_file(&owner_source_chirho).unwrap();
    let birth_source_chirho = std::fs::read_to_string(root_chirho.join(birth_path_chirho)).unwrap();
    let birth_ast_chirho = syn::parse_file(&birth_source_chirho).unwrap();
    let append_source_chirho =
        std::fs::read_to_string(root_chirho.join(append_path_chirho)).unwrap();
    let append_ast_chirho = syn::parse_file(&append_source_chirho).unwrap();
    let open_view_source_chirho =
        std::fs::read_to_string(root_chirho.join(open_view_path_chirho)).unwrap();
    let open_view_ast_chirho = syn::parse_file(&open_view_source_chirho).unwrap();
    let birth_module_chirho = owner_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Mod(module_chirho) if module_chirho.ident == "birth_chirho" => {
                Some(module_chirho)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(birth_module_chirho.len(), 1);
    assert!(matches!(birth_module_chirho[0].vis, Visibility::Inherited));
    assert!(!has_exact_cfg_test_chirho(&birth_module_chirho[0].attrs));
    let local_port_fields_chirho = owner_ast_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            Item::Struct(struct_chirho)
                if struct_chirho.ident == "ResidentLedgerLocalPortsChirho" =>
            {
                Some(
                    struct_chirho
                        .fields
                        .iter()
                        .map(|field_chirho| {
                            (
                                field_chirho
                                    .ident
                                    .as_ref()
                                    .expect("resident local port must be named")
                                    .to_string(),
                                canonical_type_path_chirho(&field_chirho.ty),
                            )
                        })
                        .collect::<BTreeSet<_>>(),
                )
            }
            _ => None,
        })
        .expect("resident local port bundle must exist");
    assert_eq!(
        local_port_fields_chirho,
        BTreeSet::from([
            (
                "authority_chirho".to_owned(),
                "PlatformPolicyMintAuthorityChirho".to_owned(),
            ),
            (
                "clock_chirho".to_owned(),
                "ResidentLedgerClockChirho".to_owned()
            ),
            (
                "kind_registry_chirho".to_owned(),
                "VerifiedRegistryChirho".to_owned()
            ),
            (
                "membership_chirho".to_owned(),
                "ElectedClusterMembershipChirho".to_owned(),
            ),
            (
                "signer_chirho".to_owned(),
                "RoleBoundLedgerSignerChirho".to_owned(),
            ),
            (
                "storage_chirho".to_owned(),
                "FsLedgerStorageChirho".to_owned()
            ),
        ]),
        "resident authority ports must remain exact concrete local adapters"
    );
    let public_methods_chirho = owner_ast_chirho
        .items
        .iter()
        .chain(birth_ast_chirho.items.iter())
        .chain(append_ast_chirho.items.iter())
        .chain(open_view_ast_chirho.items.iter())
        .filter_map(|item_chirho| match item_chirho {
            Item::Impl(implementation_chirho)
                if canonical_type_path_chirho(&implementation_chirho.self_ty)
                    == "ResidentLedgerAuthorityChirho" =>
            {
                Some(&implementation_chirho.items)
            }
            _ => None,
        })
        .flatten()
        .filter_map(|item_chirho| match item_chirho {
            syn::ImplItem::Fn(function_chirho)
                if matches!(function_chirho.vis, Visibility::Public(_)) =>
            {
                Some(function_chirho)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        public_methods_chirho
            .iter()
            .map(|function_chirho| function_chirho.sig.ident.to_string())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "append_preactivation_chirho".to_owned(),
            "create_bound_preactivation_chirho".to_owned(),
            "open_bound_preactivation_chirho".to_owned(),
            "probe_chirho".to_owned(),
            "seal_gd7_winner_current_view_chirho".to_owned(),
            "stage_next_gd7_winner_view_bundle_page_chirho".to_owned(),
        ]),
        "resident authority must expose only exact sealed birth, open, probe, append, and proof-only current-view methods"
    );
    let open_chirho = public_methods_chirho
        .iter()
        .find(|function_chirho| function_chirho.sig.ident == "open_bound_preactivation_chirho")
        .expect("resident authority open must exist");
    let open_parameters_chirho = open_chirho
        .sig
        .inputs
        .iter()
        .filter_map(|argument_chirho| match argument_chirho {
            syn::FnArg::Typed(argument_chirho) => {
                let syn::Pat::Ident(name_chirho) = argument_chirho.pat.as_ref() else {
                    panic!("resident authority input must use one named binding");
                };
                Some((
                    name_chirho.ident.to_string(),
                    canonical_type_path_chirho(&argument_chirho.ty),
                ))
            }
            syn::FnArg::Receiver(_) => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        open_parameters_chirho,
        vec![
            ("root_chirho".to_owned(), "Path".to_owned()),
            (
                "ports_chirho".to_owned(),
                "ResidentLedgerLocalPortsChirho".to_owned(),
            ),
            (
                "journal_path_chirho".to_owned(),
                "StoragePathChirho".to_owned(),
            ),
            (
                "expected_cluster_chirho".to_owned(),
                "ClusterIdChirho".to_owned(),
            ),
            ("expected_opening_epoch_chirho".to_owned(), "u64".to_owned()),
            (
                "local_authority_chirho".to_owned(),
                "LocalAppendAuthorityHandleChirho".to_owned(),
            ),
        ],
        "resident open inputs must stay exact concrete local coordinates with no injected writer or callback"
    );

    let stage_bundle_page_chirho = public_methods_chirho
        .iter()
        .find(|function_chirho| {
            function_chirho.sig.ident == "stage_next_gd7_winner_view_bundle_page_chirho"
        })
        .expect("bounded resident winner-view page stager must exist");
    assert!(
        stage_bundle_page_chirho.sig.asyncness.is_none()
            && stage_bundle_page_chirho.sig.constness.is_none()
            && stage_bundle_page_chirho.sig.unsafety.is_none()
            && stage_bundle_page_chirho.sig.abi.is_none()
            && stage_bundle_page_chirho.sig.variadic.is_none()
            && stage_bundle_page_chirho.sig.generics.params.is_empty()
            && stage_bundle_page_chirho.sig.generics.where_clause.is_none(),
        "bounded resident winner-view page staging must remain synchronous, nongeneric, and callback-free"
    );
    let stage_bundle_page_receiver_chirho = stage_bundle_page_chirho
        .sig
        .inputs
        .first()
        .expect("bounded resident winner-view page stager must take a receiver");
    assert!(
        matches!(
            stage_bundle_page_receiver_chirho,
            syn::FnArg::Receiver(receiver_chirho)
                if receiver_chirho.reference.is_some() && receiver_chirho.mutability.is_none()
        ),
        "bounded resident winner-view page staging must immutably borrow its retained authority owner"
    );
    let stage_bundle_page_parameters_chirho = stage_bundle_page_chirho
        .sig
        .inputs
        .iter()
        .filter_map(|argument_chirho| match argument_chirho {
            syn::FnArg::Typed(argument_chirho) => {
                let syn::Pat::Ident(name_chirho) = argument_chirho.pat.as_ref() else {
                    panic!("bounded resident winner-view page input must use one named binding");
                };
                Some((
                    name_chirho.ident.to_string(),
                    canonical_type_path_chirho(&argument_chirho.ty),
                ))
            }
            syn::FnArg::Receiver(_) => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        stage_bundle_page_parameters_chirho,
        vec![(
            "restart_chirho".to_owned(),
            "Option<Gd7WinnerViewBundleRestartChirho>".to_owned(),
        )],
        "bounded resident winner-view page staging must accept only its opaque in-process continuation"
    );

    let append_chirho = public_methods_chirho
        .iter()
        .find(|function_chirho| function_chirho.sig.ident == "append_preactivation_chirho")
        .expect("sealed resident append must exist");
    assert!(
        append_chirho.sig.asyncness.is_none()
            && append_chirho.sig.constness.is_none()
            && append_chirho.sig.unsafety.is_none()
            && append_chirho.sig.abi.is_none()
            && append_chirho.sig.variadic.is_none()
            && append_chirho.sig.generics.params.is_empty()
            && append_chirho.sig.generics.where_clause.is_none(),
        "sealed resident append must remain synchronous, nongeneric, and callback-free"
    );
    let append_receiver_chirho = append_chirho
        .sig
        .inputs
        .first()
        .expect("sealed resident append must take a receiver");
    assert!(
        matches!(
            append_receiver_chirho,
            syn::FnArg::Receiver(receiver_chirho)
                if receiver_chirho.reference.is_some() && receiver_chirho.mutability.is_some()
        ),
        "sealed resident append must exclusively borrow its retained authority owner"
    );
    let append_parameters_chirho = append_chirho
        .sig
        .inputs
        .iter()
        .filter_map(|argument_chirho| match argument_chirho {
            syn::FnArg::Typed(argument_chirho) => {
                let syn::Pat::Ident(name_chirho) = argument_chirho.pat.as_ref() else {
                    panic!("sealed resident append input must use one named binding");
                };
                Some((
                    name_chirho.ident.to_string(),
                    canonical_type_path_chirho(&argument_chirho.ty),
                ))
            }
            syn::FnArg::Receiver(_) => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        append_parameters_chirho,
        vec![
            (
                "_permit_chirho".to_owned(),
                "ResidentLedgerAppendPermitChirho".to_owned(),
            ),
            (
                "request_chirho".to_owned(),
                "AppendRequestChirho".to_owned(),
            ),
        ],
        "sealed resident append must accept only the unconstructible permit and one typed request"
    );
    let syn::ReturnType::Type(_, append_output_chirho) = &append_chirho.sig.output else {
        panic!("sealed resident append must return its typed receipt or refusal");
    };
    let Type::Path(append_output_path_chirho) = append_output_chirho.as_ref() else {
        panic!("sealed resident append output must be one Result path");
    };
    let append_result_chirho = append_output_path_chirho
        .path
        .segments
        .last()
        .expect("sealed resident append Result segment must exist");
    assert_eq!(append_result_chirho.ident, "Result");
    let PathArguments::AngleBracketed(append_result_arguments_chirho) =
        &append_result_chirho.arguments
    else {
        panic!("sealed resident append Result must carry exact receipt and refusal types");
    };
    let append_result_types_chirho = append_result_arguments_chirho
        .args
        .iter()
        .map(|argument_chirho| match argument_chirho {
            GenericArgument::Type(type_chirho) => canonical_type_path_chirho(type_chirho),
            _ => panic!("sealed resident append Result gained a non-type argument"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        append_result_types_chirho,
        vec![
            "ResidentLedgerAppendReceiptChirho".to_owned(),
            "ResidentLedgerAuthorityRefusalChirho".to_owned(),
        ],
        "sealed resident append must return the fence-bound receipt and typed refusal"
    );

    let permit_fields_chirho = owner_ast_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            Item::Struct(struct_chirho)
                if struct_chirho.ident == "ResidentLedgerAppendPermitChirho" =>
            {
                assert!(matches!(struct_chirho.vis, Visibility::Public(_)));
                Some(
                    struct_chirho
                        .fields
                        .iter()
                        .map(|field_chirho| {
                            assert!(matches!(field_chirho.vis, Visibility::Inherited));
                            (
                                field_chirho
                                    .ident
                                    .as_ref()
                                    .expect("sealed permit field must be named")
                                    .to_string(),
                                matches!(field_chirho.ty, Type::Tuple(ref tuple_chirho) if tuple_chirho.elems.is_empty()),
                            )
                        })
                        .collect::<BTreeSet<_>>(),
                )
            }
            _ => None,
        })
        .expect("sealed resident append permit must exist");
    assert_eq!(
        permit_fields_chirho,
        BTreeSet::from([("_sealed_chirho".to_owned(), true)]),
        "the public permit type must remain impossible to construct outside its owner"
    );
    let permit_constructors_chirho = owner_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Impl(implementation_chirho)
                if canonical_type_path_chirho(&implementation_chirho.self_ty)
                    == "ResidentLedgerAppendPermitChirho" =>
            {
                Some(&implementation_chirho.items)
            }
            _ => None,
        })
        .flatten()
        .filter_map(|item_chirho| match item_chirho {
            syn::ImplItem::Fn(function_chirho) => Some((
                function_chirho.sig.ident.to_string(),
                visibility_is_crate_chirho(&function_chirho.vis),
                has_exact_cfg_test_chirho(&function_chirho.attrs),
            )),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        permit_constructors_chirho,
        BTreeSet::from([("for_test_chirho".to_owned(), true, true)]),
        "the sealed resident append permit must have one crate-private test-only constructor"
    );

    #[derive(Default)]
    struct ResidentAppendPermitStructVisitorChirho {
        permit_struct_expressions_chirho: usize,
    }
    impl<'ast_chirho> Visit<'ast_chirho> for ResidentAppendPermitStructVisitorChirho {
        fn visit_expr_struct(&mut self, expression_chirho: &'ast_chirho syn::ExprStruct) {
            if expression_chirho
                .path
                .segments
                .last()
                .is_some_and(|segment_chirho| {
                    segment_chirho.ident == "ResidentLedgerAppendPermitChirho"
                })
            {
                self.permit_struct_expressions_chirho += 1;
            }
            syn::visit::visit_expr_struct(self, expression_chirho);
        }
    }
    let mut permit_reference_paths_chirho = BTreeSet::new();
    let mut production_append_permit_structs_chirho =
        ResidentAppendPermitStructVisitorChirho::default();
    for path_chirho in workspace_production_rs_files_chirho() {
        let raw_source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let source_chirho = production_text_chirho(&raw_source_chirho);
        let has_permit_reference_chirho =
            source_chirho.contains("ResidentLedgerAppendPermitChirho");
        let has_append_reference_chirho = source_chirho.contains("append_preactivation_chirho");
        if has_permit_reference_chirho {
            permit_reference_paths_chirho.insert(workspace_relative_chirho(&path_chirho));
        }
        if !has_permit_reference_chirho && !has_append_reference_chirho {
            continue;
        }
        let ast_chirho = syn::parse_file(&source_chirho).unwrap_or_else(|error_chirho| {
            panic!(
                "resident append production inventory must parse {}: {error_chirho}",
                workspace_relative_chirho(&path_chirho)
            )
        });
        production_append_permit_structs_chirho.visit_file(&ast_chirho);
    }
    assert_eq!(
        permit_reference_paths_chirho,
        BTreeSet::from([
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/lib.rs".to_owned(),
            activation_path_chirho.to_owned(),
            append_path_chirho.to_owned(),
            owner_path_chirho.to_owned(),
        ]),
        "production append-permit references must remain confined to its owner, reviewed activation capsule, and public type export"
    );
    let h3_inventory_chirho = h3_target_inventory_chirho();
    assert!(
        h3_inventory_chirho.unresolved_chirho.is_empty(),
        "H3 capability references must resolve to reviewed target symbols; unresolved forms fail closed: {:?}",
        h3_inventory_chirho.unresolved_chirho
    );
    let append_coordinates_chirho = h3_inventory_chirho
        .coordinates_chirho
        .iter()
        .filter(|entry_chirho| entry_chirho.0 .2 == H3_APPEND_TARGET_CHIRHO)
        .map(
            |((file_chirho, owner_chirho, _target_chirho), count_chirho)| {
                (file_chirho.clone(), owner_chirho.clone(), *count_chirho)
            },
        )
        .collect::<BTreeSet<_>>();
    assert_eq!(
        append_coordinates_chirho,
        BTreeSet::from([(
            activation_path_chirho.to_owned(),
            "activate_reviewed_h3_chirho".to_owned(),
            1,
        )]),
        "sealed resident append must resolve to the one reviewed activation caller"
    );
    assert_eq!(
        production_append_permit_structs_chirho.permit_struct_expressions_chirho, 1,
        "exactly one reviewed production capsule may construct the sealed resident append permit"
    );
    let activation_source_chirho =
        std::fs::read_to_string(root_chirho.join(activation_path_chirho)).unwrap();
    let activation_ast_chirho = syn::parse_file(&activation_source_chirho).unwrap();
    let activation_function_chirho = activation_ast_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            Item::Fn(function_chirho)
                if function_chirho.sig.ident == "activate_reviewed_h3_chirho" =>
            {
                Some(function_chirho)
            }
            _ => None,
        })
        .expect("reviewed H3 activation capsule must exist");
    let mut activation_append_permit_structs_chirho =
        ResidentAppendPermitStructVisitorChirho::default();
    activation_append_permit_structs_chirho.visit_block(&activation_function_chirho.block);
    assert_eq!(
        activation_append_permit_structs_chirho.permit_struct_expressions_chirho,
        1
    );

    let resident_struct_chirho = owner_ast_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            Item::Struct(struct_chirho)
                if struct_chirho.ident == "ResidentLedgerAuthorityChirho" =>
            {
                Some(struct_chirho)
            }
            _ => None,
        })
        .expect("resident authority owner must exist");
    let resident_fields_chirho = resident_struct_chirho
        .fields
        .iter()
        .map(|field_chirho| {
            field_chirho
                .ident
                .as_ref()
                .expect("resident authority field must be named")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        resident_fields_chirho,
        BTreeSet::from([
            "active_fence_chirho".to_owned(),
            "authority_root_snapshot_chirho".to_owned(),
            "authority_storage_chirho".to_owned(),
            "canonical_root_chirho".to_owned(),
            "cluster_id_chirho".to_owned(),
            "group_chirho".to_owned(),
            "identity_storage_namespace_chirho".to_owned(),
            "journal_chirho".to_owned(),
            "journal_path_chirho".to_owned(),
            "local_authority_chirho".to_owned(),
            "local_node_chirho".to_owned(),
            "opening_epoch_chirho".to_owned(),
            "ordinary_term_acceptance_placement_binding_chirho".to_owned(),
            "ordinary_term_acceptance_source_chirho".to_owned(),
            "ports_chirho".to_owned(),
            "resident_identity_digest_chirho".to_owned(),
            "resident_lease_chirho".to_owned(),
            "storage_snapshot_chirho".to_owned(),
            "writer_lock_chirho".to_owned(),
        ]),
        "resident authority must retain the exact local authority set plus one reviewed byte-only ordinary-term receipt source and its immutable placement binding"
    );
    let ordinary_term_source_field_chirho = resident_struct_chirho
        .fields
        .iter()
        .find(|field_chirho| {
            field_chirho
                .ident
                .as_ref()
                .is_some_and(|identifier_chirho| {
                    identifier_chirho == "ordinary_term_acceptance_source_chirho"
                })
        })
        .expect("resident authority must retain the reviewed ordinary-term receipt source");
    assert!(
        is_exact_optional_arc_trait_chirho(
            &ordinary_term_source_field_chirho.ty,
            "LedgerMirrorOrdinaryTermAcceptanceEvidenceSourceChirho",
        ),
        "ordinary-term acceptance may retain only the reviewed optional byte-only receipt source trait"
    );
    let ordinary_term_binding_field_chirho = resident_struct_chirho
        .fields
        .iter()
        .find(|field_chirho| {
            field_chirho
                .ident
                .as_ref()
                .is_some_and(|identifier_chirho| {
                    identifier_chirho == "ordinary_term_acceptance_placement_binding_chirho"
                })
        })
        .expect("resident authority must retain the immutable ordinary-term placement binding");
    assert_eq!(
        canonical_type_path_chirho(&ordinary_term_binding_field_chirho.ty),
        "Option<LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho>",
        "ordinary-term acceptance placement input must remain one immutable typed binding"
    );

    let append_start_chirho = owner_source_chirho
        .find("    fn append_with_current_fence_chirho(")
        .expect("sealed append source must exist");
    let append_end_chirho = owner_source_chirho[append_start_chirho..]
        .find("\n}\n\nimpl Drop for ResidentLedgerAuthorityChirho")
        .map(|offset_chirho| append_start_chirho + offset_chirho)
        .expect("sealed append source must end before resident teardown");
    let append_source_chirho = &owner_source_chirho[append_start_chirho..append_end_chirho];
    let mut append_cursor_chirho = 0;
    for anchor_chirho in [
        "try_acquire_chirho()",
        "verify_fixed_resident_evidence_chirho()",
        "writer_lock_chirho\n            .try_acquire_chirho()",
        "read_bounded_object_chirho",
        "prepare_reused_or_issued_elected_writer_fence_chirho",
        "JournalAheadOfDurableFenceStateChirho",
        "MembershipAheadOfDurableFenceStateChirho",
        "atomic_write_chirho",
        "self.active_fence_chirho = Some",
        "advance_epoch_chirho",
        "rebind_epoch_chirho",
        "verify_custody_chirho",
        "append_chirho(request_chirho)",
    ] {
        let relative_anchor_chirho = append_source_chirho[append_cursor_chirho..]
            .find(anchor_chirho)
            .unwrap_or_else(|| {
                panic!("sealed resident append lost ordered safety anchor {anchor_chirho}")
            });
        append_cursor_chirho += relative_anchor_chirho + anchor_chirho.len();
    }

    struct ForbiddenResidentOperationVisitorChirho {
        forbidden_chirho: BTreeSet<String>,
        found_chirho: BTreeSet<String>,
    }
    impl<'ast_chirho> Visit<'ast_chirho> for ForbiddenResidentOperationVisitorChirho {
        fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
            let method_chirho = call_chirho.method.to_string();
            if self.forbidden_chirho.contains(&method_chirho) {
                self.found_chirho.insert(method_chirho);
            }
            syn::visit::visit_expr_method_call(self, call_chirho);
        }

        fn visit_expr_call(&mut self, call_chirho: &'ast_chirho syn::ExprCall) {
            if let syn::Expr::Path(path_chirho) = call_chirho.func.as_ref() {
                if let Some(segment_chirho) = path_chirho.path.segments.last() {
                    let function_chirho = segment_chirho.ident.to_string();
                    if self.forbidden_chirho.contains(&function_chirho) {
                        self.found_chirho.insert(function_chirho);
                    }
                }
            }
            syn::visit::visit_expr_call(self, call_chirho);
        }
    }
    let mut forbidden_operations_chirho = ForbiddenResidentOperationVisitorChirho {
        forbidden_chirho: BTreeSet::from([
            "append_request_chirho".to_owned(),
            "issue_elected_writer_fence_chirho".to_owned(),
            "journal_mut_chirho".to_owned(),
            "journal_ref_chirho".to_owned(),
            "rotate_chirho".to_owned(),
            "with_issued_writer_fence_for_root_chirho".to_owned(),
            "with_reused_or_issued_elected_writer_fence_chirho".to_owned(),
        ]),
        found_chirho: BTreeSet::new(),
    };
    forbidden_operations_chirho.visit_file(&owner_ast_chirho);
    forbidden_operations_chirho.visit_file(&birth_ast_chirho);
    assert!(
        forbidden_operations_chirho.found_chirho.is_empty(),
        "sealed resident append bypassed the reviewed descriptor-owned path: {:?}",
        forbidden_operations_chirho.found_chirho
    );

    let storage_source_chirho = std::fs::read_to_string(
        root_chirho
            .join("crates/ledger-chirho/host-chirho/cairn-ledger-host-storage-chirho/src/lib.rs"),
    )
    .unwrap();
    let storage_ast_chirho = syn::parse_file(&storage_source_chirho).unwrap();
    fn has_exact_cfg_unix_chirho(attributes_chirho: &[syn::Attribute]) -> bool {
        attributes_chirho.iter().any(|attribute_chirho| {
            attribute_chirho.path().is_ident("cfg")
                && attribute_chirho
                    .meta
                    .require_list()
                    .is_ok_and(|list_chirho| list_chirho.tokens.to_string() == "unix")
        })
    }
    fn is_descriptor_namespace_arc_chirho(type_chirho: &Type) -> bool {
        let Type::Path(outer_chirho) = type_chirho else {
            return false;
        };
        let Some(arc_chirho) = outer_chirho.path.segments.last() else {
            return false;
        };
        if arc_chirho.ident != "Arc" {
            return false;
        }
        let PathArguments::AngleBracketed(arguments_chirho) = &arc_chirho.arguments else {
            return false;
        };
        if arguments_chirho.args.len() != 1 {
            return false;
        }
        let Some(GenericArgument::Type(Type::Path(inner_chirho))) = arguments_chirho.args.first()
        else {
            return false;
        };
        inner_chirho
            .path
            .segments
            .iter()
            .map(|segment_chirho| segment_chirho.ident.to_string())
            .collect::<Vec<_>>()
            == [
                "descriptor_namespace_chirho".to_owned(),
                "DescriptorLedgerNamespaceChirho".to_owned(),
            ]
    }
    let descriptor_module_chirho = storage_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Mod(module_chirho) if module_chirho.ident == "descriptor_namespace_chirho" => {
                Some(module_chirho)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(descriptor_module_chirho.len(), 1);
    assert!(matches!(
        descriptor_module_chirho[0].vis,
        Visibility::Inherited
    ));
    assert!(has_exact_cfg_unix_chirho(
        &descriptor_module_chirho[0].attrs
    ));
    let unix_namespace_fields_chirho = storage_ast_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            Item::Struct(struct_chirho) if struct_chirho.ident == "FsLedgerStorageChirho" => Some(
                struct_chirho
                    .fields
                    .iter()
                    .filter(|field_chirho| has_exact_cfg_unix_chirho(&field_chirho.attrs))
                    .map(|field_chirho| {
                        (
                            field_chirho
                                .ident
                                .as_ref()
                                .expect("filesystem storage field must be named")
                                .to_string(),
                            is_descriptor_namespace_arc_chirho(&field_chirho.ty),
                        )
                    })
                    .collect::<BTreeSet<_>>(),
            ),
            _ => None,
        })
        .expect("filesystem storage adapter must exist");
    assert_eq!(
        unix_namespace_fields_chirho,
        BTreeSet::from([("namespace_chirho".to_owned(), true)]),
        "Unix filesystem storage must retain exactly one O(1)-clone descriptor owner"
    );

    let descriptor_source_chirho = std::fs::read_to_string(root_chirho.join(
        "crates/ledger-chirho/host-chirho/cairn-ledger-host-storage-chirho/src/descriptor_namespace_chirho.rs",
    ))
    .unwrap();
    let descriptor_ast_chirho = syn::parse_file(&descriptor_source_chirho).unwrap();
    let stable_snapshot_methods_chirho = descriptor_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Impl(implementation_chirho)
                if canonical_type_path_chirho(&implementation_chirho.self_ty)
                    == "StableLedgerNamespaceSnapshotChirho" =>
            {
                Some(&implementation_chirho.items)
            }
            _ => None,
        })
        .flatten()
        .filter_map(|item_chirho| match item_chirho {
            // `pub` is admitted ALONGSIDE `pub(crate)` because the storage adapter now lives in its
            // own crate and a crate boundary cannot carry `pub(crate)`. The PREDICATE below is
            // unchanged — the same four methods, the same cfg-gating expectations. Narrowing the
            // expected SET to match the new visibility would have deleted two methods from this
            // guard's watch, which is how a guard gets gutted by a refactor.
            syn::ImplItem::Fn(function_chirho)
                if visibility_is_crate_chirho(&function_chirho.vis)
                    || matches!(function_chirho.vis, Visibility::Public(_)) =>
            {
                Some((
                    function_chirho.sig.ident.to_string(),
                    function_chirho
                        .attrs
                        .iter()
                        .any(|attribute_chirho| attribute_chirho.path().is_ident("cfg")),
                ))
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        stable_snapshot_methods_chirho,
        BTreeSet::from([
            ("acquire_existing_chirho".to_owned(), true),
            ("identity_chirho".to_owned(), false),
            ("open_mutable_target_chirho".to_owned(), true),
            ("verify_current_path_chirho".to_owned(), false),
        ]),
        "the stable snapshot API must remain retained-owner derived on Unix; independent open and direct mutable target access stay cfg-gated"
    );

    let descriptor_methods_chirho = descriptor_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Impl(implementation_chirho)
                if canonical_type_path_chirho(&implementation_chirho.self_ty)
                    == "DescriptorLedgerNamespaceChirho" =>
            {
                Some(&implementation_chirho.items)
            }
            _ => None,
        })
        .flatten()
        .filter_map(|item_chirho| match item_chirho {
            syn::ImplItem::Fn(function_chirho)
                if matches!(
                    &function_chirho.vis,
                    Visibility::Restricted(restricted_chirho)
                        if restricted_chirho.path.segments.len() == 1
                            && restricted_chirho.path.segments[0].ident == "super"
                ) =>
            {
                Some(function_chirho.sig.ident.to_string())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let storage_operations_chirho = BTreeSet::from([
        "append_durable_chirho".to_owned(),
        "atomic_write_chirho".to_owned(),
        "create_durable_chirho".to_owned(),
        "exists_chirho".to_owned(),
        "list_chirho".to_owned(),
        "object_len_chirho".to_owned(),
        "read_all_chirho".to_owned(),
        "read_exact_range_chirho".to_owned(),
        "remove_chirho".to_owned(),
        "rename_chirho".to_owned(),
        "truncate_durable_chirho".to_owned(),
    ]);
    let mut expected_descriptor_methods_chirho = storage_operations_chirho.clone();
    expected_descriptor_methods_chirho.extend([
        "canonical_root_chirho".to_owned(),
        "clone_root_directory_chirho".to_owned(),
        "open_existing_exclusive_lock_handle_chirho".to_owned(),
        "open_existing_chirho".to_owned(),
        "read_bounded_object_chirho".to_owned(),
        "stable_snapshot_chirho".to_owned(),
    ]);
    assert_eq!(
        descriptor_methods_chirho, expected_descriptor_methods_chirho,
        "the Unix descriptor owner gained or lost a reviewed namespace operation"
    );

    let descriptor_lock_fields_chirho = descriptor_ast_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            Item::Struct(struct_chirho)
                if struct_chirho.ident == "DescriptorLedgerExclusiveLockHandleChirho" =>
            {
                Some(
                    struct_chirho
                        .fields
                        .iter()
                        .map(|field_chirho| {
                            field_chirho
                                .ident
                                .as_ref()
                                .expect("descriptor lock field must be named")
                                .to_string()
                        })
                        .collect::<BTreeSet<_>>(),
                )
            }
            _ => None,
        })
        .expect("descriptor-owned lock handle must exist");
    assert_eq!(
        descriptor_lock_fields_chirho,
        BTreeSet::from([
            "lock_file_chirho".to_owned(),
            "lock_identity_chirho".to_owned(),
            "lock_name_chirho".to_owned(),
            "namespace_chirho".to_owned(),
            "parent_directory_chirho".to_owned(),
            "parent_identity_chirho".to_owned(),
        ]),
        "descriptor lock must retain the exact inode, parent, name, and namespace owner without a registry"
    );
    let descriptor_lock_methods_chirho = descriptor_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Impl(implementation_chirho)
                if canonical_type_path_chirho(&implementation_chirho.self_ty)
                    == "DescriptorLedgerExclusiveLockHandleChirho" =>
            {
                Some(&implementation_chirho.items)
            }
            _ => None,
        })
        .flatten()
        .filter_map(|item_chirho| match item_chirho {
            syn::ImplItem::Fn(function_chirho) => Some(function_chirho.sig.ident.to_string()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        descriptor_lock_methods_chirho,
        BTreeSet::from([
            "try_acquire_chirho".to_owned(),
            "verify_custody_chirho".to_owned(),
        ]),
        "descriptor lock handle must expose only nonblocking acquisition and custody verification"
    );
    assert!(
        descriptor_source_chirho.contains("FlockOperation::NonBlockingLockExclusive")
            && descriptor_source_chirho.contains("ExclusiveLockBusyChirho")
            && descriptor_source_chirho.contains("FlockOperation::Unlock"),
        "descriptor lock must fail busy without blocking and release through its private guard"
    );

    #[derive(Default)]
    struct ReviewedMethodCallVisitorChirho {
        calls_chirho: BTreeMap<String, usize>,
    }
    impl<'ast_chirho> Visit<'ast_chirho> for ReviewedMethodCallVisitorChirho {
        fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
            *self
                .calls_chirho
                .entry(call_chirho.method.to_string())
                .or_default() += 1;
            syn::visit::visit_expr_method_call(self, call_chirho);
        }
    }
    let reviewed_descriptor_method_calls_chirho = descriptor_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Impl(implementation_chirho)
                if canonical_type_path_chirho(&implementation_chirho.self_ty)
                    == "DescriptorLedgerNamespaceChirho" =>
            {
                Some(&implementation_chirho.items)
            }
            _ => None,
        })
        .flatten()
        .filter_map(|item_chirho| match item_chirho {
            syn::ImplItem::Fn(function_chirho)
                if [
                    "open_existing_exclusive_lock_handle_chirho",
                    "read_bounded_object_chirho",
                ]
                .contains(&function_chirho.sig.ident.to_string().as_str()) =>
            {
                let mut visitor_chirho = ReviewedMethodCallVisitorChirho::default();
                visitor_chirho.visit_block(&function_chirho.block);
                Some((
                    function_chirho.sig.ident.to_string(),
                    visitor_chirho.calls_chirho,
                ))
            }
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let lock_open_calls_chirho = reviewed_descriptor_method_calls_chirho
        .get("open_existing_exclusive_lock_handle_chirho")
        .expect("descriptor lock opener must remain inventoried");
    assert_eq!(
        lock_open_calls_chirho.get("open_parent_target_chirho"),
        Some(&1)
    );
    assert_eq!(
        lock_open_calls_chirho.get("open_existing_file_chirho"),
        Some(&1)
    );
    assert_eq!(lock_open_calls_chirho.get("create_new_file_chirho"), None);
    let bounded_read_calls_chirho = reviewed_descriptor_method_calls_chirho
        .get("read_bounded_object_chirho")
        .expect("descriptor bounded reader must remain inventoried");
    assert_eq!(
        bounded_read_calls_chirho.get("open_parent_target_chirho"),
        Some(&1)
    );
    assert_eq!(
        bounded_read_calls_chirho.get("open_optional_existing_file_chirho"),
        Some(&1)
    );
    assert_eq!(bounded_read_calls_chirho.get("object_len_chirho"), None);
    assert_eq!(
        bounded_read_calls_chirho.get("read_exact_range_chirho"),
        None
    );

    struct NamespaceDelegationVisitorChirho {
        calls_chirho: BTreeSet<String>,
    }
    impl<'ast_chirho> Visit<'ast_chirho> for NamespaceDelegationVisitorChirho {
        fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
            if matches!(
                call_chirho.receiver.as_ref(),
                syn::Expr::Field(field_chirho)
                    if matches!(
                        field_chirho.base.as_ref(),
                        syn::Expr::Path(path_chirho) if path_chirho.path.is_ident("self")
                    ) && matches!(
                        &field_chirho.member,
                        syn::Member::Named(name_chirho) if name_chirho == "namespace_chirho"
                    )
            ) {
                self.calls_chirho.insert(call_chirho.method.to_string());
            }
            syn::visit::visit_expr_method_call(self, call_chirho);
        }
    }
    let storage_delegations_chirho = storage_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Impl(implementation_chirho)
                if implementation_chirho.trait_.as_ref().is_some_and(
                    |(_bang_chirho, path_chirho, _for_chirho)| {
                        path_chirho.segments.last().is_some_and(|segment_chirho| {
                            segment_chirho.ident == "LedgerStoragePortChirho"
                        })
                    },
                ) && canonical_type_path_chirho(&implementation_chirho.self_ty)
                    == "FsLedgerStorageChirho" =>
            {
                Some(&implementation_chirho.items)
            }
            _ => None,
        })
        .flatten()
        .filter_map(|item_chirho| match item_chirho {
            syn::ImplItem::Fn(function_chirho) => Some(function_chirho),
            _ => None,
        })
        .map(|function_chirho| {
            let mut visitor_chirho = NamespaceDelegationVisitorChirho {
                calls_chirho: BTreeSet::new(),
            };
            visitor_chirho.visit_block(&function_chirho.block);
            (
                function_chirho.sig.ident.to_string(),
                visitor_chirho.calls_chirho,
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        storage_delegations_chirho,
        storage_operations_chirho
            .iter()
            .map(|operation_chirho| {
                (
                    operation_chirho.clone(),
                    BTreeSet::from([operation_chirho.clone()]),
                )
            })
            .collect::<BTreeMap<_, _>>(),
        "every Unix filesystem storage operation must delegate to the retained descriptor owner"
    );

    struct SnapshotReuseVisitorChirho {
        found_chirho: bool,
    }
    impl<'ast_chirho> Visit<'ast_chirho> for SnapshotReuseVisitorChirho {
        fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
            if call_chirho.method == "stable_namespace_snapshot_chirho" {
                self.found_chirho = true;
            }
            syn::visit::visit_expr_method_call(self, call_chirho);
        }
    }
    let mut snapshot_reuse_coordinates_chirho = BTreeSet::new();
    for path_chirho in [
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho.rs",
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/birth_chirho.rs",
        open_view_path_chirho,
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/elected_authority_chirho.rs",
    ] {
        let source_chirho = std::fs::read_to_string(root_chirho.join(path_chirho)).unwrap();
        let ast_chirho = syn::parse_file(&source_chirho).unwrap();
        for item_chirho in &ast_chirho.items {
            let Item::Impl(implementation_chirho) = item_chirho else {
                continue;
            };
            for implementation_item_chirho in &implementation_chirho.items {
                let syn::ImplItem::Fn(function_chirho) = implementation_item_chirho else {
                    continue;
                };
                let mut visitor_chirho = SnapshotReuseVisitorChirho {
                    found_chirho: false,
                };
                visitor_chirho.visit_block(&function_chirho.block);
                if visitor_chirho.found_chirho {
                    snapshot_reuse_coordinates_chirho.insert((
                        path_chirho.to_owned(),
                        function_chirho.sig.ident.to_string(),
                    ));
                }
            }
        }
    }
    assert_eq!(
        snapshot_reuse_coordinates_chirho,
        BTreeSet::from([
            (
                "crates/ledger-chirho/cairn-ledger-host-chirho/src/elected_authority_chirho.rs"
                    .to_owned(),
                "create_chirho".to_owned(),
            ),
            (
                "crates/ledger-chirho/cairn-ledger-host-chirho/src/elected_authority_chirho.rs"
                    .to_owned(),
                "open_chirho".to_owned(),
            ),
            (
                "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/birth_chirho.rs"
                    .to_owned(),
                "create_bound_preactivation_chirho".to_owned(),
            ),
            (
                open_view_path_chirho.to_owned(),
                "open_bound_preactivation_chirho".to_owned(),
            ),
        ]),
        "reviewed authorities must reuse the storage adapter's retained namespace descriptor"
    );
}

fn assert_resident_identity_types_are_non_debug_chirho(owner_ast_chirho: &syn::File) {
    let sensitive_types_chirho = BTreeSet::from([
        "ResidentLedgerCoordinateSourceChirho",
        "VerifiedResidentLedgerBoundIdentityChirho",
        "VerifiedResidentLedgerPendingIdentityChirho",
        "ResidentLedgerCoordinateChirho",
        "ResidentLedgerIdentityStateChirho",
        "ResidentLedgerPendingIdentityChirho",
        "ResidentLedgerBoundIdentityChirho",
    ]);
    for item_chirho in &owner_ast_chirho.items {
        let (name_chirho, attributes_chirho) = match item_chirho {
            Item::Struct(struct_chirho) => (struct_chirho.ident.to_string(), &struct_chirho.attrs),
            Item::Enum(enum_chirho) => (enum_chirho.ident.to_string(), &enum_chirho.attrs),
            _ => continue,
        };
        if sensitive_types_chirho.contains(name_chirho.as_str()) {
            assert!(
                !attributes_chirho.iter().any(attribute_derives_debug_chirho),
                "resident identity type {name_chirho} must not derive Debug"
            );
        }
    }
    for item_chirho in &owner_ast_chirho.items {
        let Item::Impl(implementation_chirho) = item_chirho else {
            continue;
        };
        let Some((_bang_chirho, trait_path_chirho, _for_chirho)) = &implementation_chirho.trait_
        else {
            continue;
        };
        if trait_path_chirho
            .segments
            .last()
            .is_none_or(|segment_chirho| segment_chirho.ident != "Debug")
        {
            continue;
        }
        let syn::Type::Path(type_chirho) = implementation_chirho.self_ty.as_ref() else {
            continue;
        };
        let type_name_chirho = type_chirho
            .path
            .segments
            .last()
            .map(|segment_chirho| segment_chirho.ident.to_string());
        assert!(
            !type_name_chirho
                .as_deref()
                .is_some_and(|name_chirho| sensitive_types_chirho.contains(name_chirho)),
            "resident identity type must not implement Debug"
        );
    }
}

fn attribute_derives_debug_chirho(attribute_chirho: &syn::Attribute) -> bool {
    if !attribute_chirho.path().is_ident("derive") {
        return false;
    }
    let mut derives_debug_chirho = false;
    let _parse_result_chirho = attribute_chirho.parse_nested_meta(|meta_chirho| {
        if meta_chirho
            .path
            .segments
            .last()
            .is_some_and(|segment_chirho| segment_chirho.ident == "Debug")
        {
            derives_debug_chirho = true;
        }
        Ok(())
    });
    derives_debug_chirho
}

#[derive(Default)]
pub(super) struct IdentityKeyCallVisitorChirho {
    existing_calls_chirho: BTreeSet<String>,
    creating_calls_chirho: BTreeSet<String>,
    signer_targets_chirho: BTreeSet<String>,
    unresolved_signer_targets_chirho: BTreeSet<String>,
    direct_reference_pairs_chirho: BTreeSet<String>,
    current_function_chirho: Option<String>,
}

impl<'ast_chirho> Visit<'ast_chirho> for IdentityKeyCallVisitorChirho {
    fn visit_expr_path(&mut self, path_chirho: &'ast_chirho syn::ExprPath) {
        classify_signer_path_chirho(&path_chirho.path, self);
        if let Some(segment_chirho) = path_chirho.path.segments.last() {
            let name_chirho = segment_chirho.ident.to_string();
            if matches!(
                name_chirho.as_str(),
                "sign_with_existing_key_possession_chirho" | "verify_with_pubkey_chirho"
            ) {
                if let Some(function_chirho) = &self.current_function_chirho {
                    self.direct_reference_pairs_chirho
                        .insert(format!("{function_chirho}->{name_chirho}"));
                } else {
                    self.unresolved_signer_targets_chirho
                        .insert(format!("signer-reference-outside-function:{name_chirho}"));
                }
            }
            classify_identity_key_name_chirho(name_chirho, self);
        }
        syn::visit::visit_expr_path(self, path_chirho);
    }

    fn visit_item_fn(&mut self, function_chirho: &'ast_chirho syn::ItemFn) {
        let previous_chirho = self
            .current_function_chirho
            .replace(function_chirho.sig.ident.to_string());
        self.visit_block(&function_chirho.block);
        self.current_function_chirho = previous_chirho;
    }

    fn visit_item_use(&mut self, use_chirho: &'ast_chirho syn::ItemUse) {
        let mut paths_chirho = BTreeSet::new();
        collect_use_target_paths_chirho(&use_chirho.tree, &mut Vec::new(), &mut paths_chirho);
        for path_chirho in paths_chirho {
            classify_signer_target_path_chirho(&path_chirho, self);
        }
        syn::visit::visit_item_use(self, use_chirho);
    }
}
