// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::exact_target_reference_resolver_chirho::{
    h3_target_inventory_chirho, H3_ACTIVATION_TARGET_CHIRHO, H3_AUTHOR_TARGET_CHIRHO,
};
use super::*;

fn activation_ident_name_chirho(ident_chirho: &syn::Ident) -> String {
    let rendered_chirho = ident_chirho.to_string();
    rendered_chirho
        .strip_prefix("r#")
        .unwrap_or(&rendered_chirho)
        .to_owned()
}

#[derive(Default)]
struct ActivationBoundaryNameVisitorChirho {
    names_chirho: BTreeMap<String, usize>,
}

impl ActivationBoundaryNameVisitorChirho {
    fn record_chirho(&mut self, name_chirho: String) {
        *self.names_chirho.entry(name_chirho).or_insert(0) += 1;
    }
}

impl<'ast_chirho> Visit<'ast_chirho> for ActivationBoundaryNameVisitorChirho {
    fn visit_path(&mut self, path_chirho: &'ast_chirho syn::Path) {
        for segment_chirho in &path_chirho.segments {
            self.record_chirho(activation_ident_name_chirho(&segment_chirho.ident));
        }
        syn::visit::visit_path(self, path_chirho);
    }

    fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
        self.record_chirho(activation_ident_name_chirho(&call_chirho.method));
        syn::visit::visit_expr_method_call(self, call_chirho);
    }

    fn visit_expr_field(&mut self, field_chirho: &'ast_chirho syn::ExprField) {
        if let syn::Member::Named(name_chirho) = &field_chirho.member {
            self.record_chirho(activation_ident_name_chirho(name_chirho));
        }
        syn::visit::visit_expr_field(self, field_chirho);
    }

    fn visit_macro(&mut self, macro_chirho: &'ast_chirho syn::Macro) {
        fn record_tokens_chirho(
            visitor_chirho: &mut ActivationBoundaryNameVisitorChirho,
            stream_chirho: proc_macro2::TokenStream,
        ) {
            for token_chirho in stream_chirho {
                match token_chirho {
                    proc_macro2::TokenTree::Ident(ident_chirho) => {
                        visitor_chirho.record_chirho(activation_ident_name_chirho(&ident_chirho));
                    }
                    proc_macro2::TokenTree::Group(group_chirho) => {
                        record_tokens_chirho(visitor_chirho, group_chirho.stream());
                    }
                    proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
                }
            }
        }
        record_tokens_chirho(self, macro_chirho.tokens.clone());
        syn::visit::visit_macro(self, macro_chirho);
    }
}

fn direct_eager_call_name_chirho(statement_chirho: &syn::Stmt) -> Option<String> {
    fn peel_expression_chirho(mut expression_chirho: &syn::Expr) -> &syn::Expr {
        loop {
            expression_chirho = match expression_chirho {
                syn::Expr::Group(group_chirho) => &group_chirho.expr,
                syn::Expr::Paren(paren_chirho) => &paren_chirho.expr,
                syn::Expr::Try(try_chirho) => &try_chirho.expr,
                _ => return expression_chirho,
            };
        }
    }

    let syn::Stmt::Local(local_chirho) = statement_chirho else {
        return None;
    };
    let initializer_chirho = local_chirho.init.as_ref()?;
    let syn::Expr::Call(call_chirho) = peel_expression_chirho(&initializer_chirho.expr) else {
        return None;
    };
    let syn::Expr::Path(path_chirho) = peel_expression_chirho(&call_chirho.func) else {
        return None;
    };
    path_chirho
        .path
        .segments
        .last()
        .map(|segment_chirho| activation_ident_name_chirho(&segment_chirho.ident))
}

fn activation_boundary_function_chirho<'ast_chirho>(
    syntax_chirho: &'ast_chirho syn::File,
    name_chirho: &str,
) -> &'ast_chirho syn::ItemFn {
    syntax_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            Item::Fn(function_chirho) if function_chirho.sig.ident == name_chirho => {
                Some(function_chirho)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing activation-boundary function {name_chirho}"))
}

fn activation_boundary_names_chirho(function_chirho: &syn::ItemFn) -> BTreeMap<String, usize> {
    let mut visitor_chirho = ActivationBoundaryNameVisitorChirho::default();
    visitor_chirho.visit_block(&function_chirho.block);
    visitor_chirho.names_chirho
}

fn activation_name_owners_chirho(
    syntax_chirho: &syn::File,
    name_chirho: &str,
) -> BTreeMap<String, usize> {
    let mut owners_chirho = BTreeMap::new();
    for item_chirho in &syntax_chirho.items {
        match item_chirho {
            Item::Fn(function_chirho) => {
                let count_chirho = activation_boundary_names_chirho(function_chirho)
                    .get(name_chirho)
                    .copied()
                    .unwrap_or(0);
                if count_chirho > 0 {
                    owners_chirho.insert(function_chirho.sig.ident.to_string(), count_chirho);
                }
            }
            Item::Impl(implementation_chirho) => {
                let owner_type_chirho = match implementation_chirho.self_ty.as_ref() {
                    syn::Type::Path(path_chirho) => path_chirho
                        .path
                        .segments
                        .last()
                        .map(|segment_chirho| segment_chirho.ident.to_string())
                        .unwrap_or_else(|| "<impl>".to_owned()),
                    _ => "<impl>".to_owned(),
                };
                for implementation_item_chirho in &implementation_chirho.items {
                    let syn::ImplItem::Fn(function_chirho) = implementation_item_chirho else {
                        continue;
                    };
                    let mut visitor_chirho = ActivationBoundaryNameVisitorChirho::default();
                    visitor_chirho.visit_block(&function_chirho.block);
                    let count_chirho = visitor_chirho
                        .names_chirho
                        .get(name_chirho)
                        .copied()
                        .unwrap_or(0);
                    if count_chirho > 0 {
                        owners_chirho.insert(
                            format!("{owner_type_chirho}::{}", function_chirho.sig.ident),
                            count_chirho,
                        );
                    }
                }
            }
            _ => {}
        }
    }
    owners_chirho
}

#[test]
fn reviewed_h3_activation_has_one_exact_production_caller_chirho() {
    const ACTIVATION_SYMBOL_CHIRHO: &str = "activate_reviewed_h3_chirho";
    const ACTIVATION_PATH_CHIRHO: &str =
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/activation_chirho.rs";
    const HOST_LIB_PATH_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-host-chirho/src/lib.rs";
    const RESIDENT_OWNER_PATH_CHIRHO: &str =
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho.rs";
    const MONEY_STAGE_PATH_CHIRHO: &str =
        "crates/ledger-chirho/cairn-ledger-regenesis-chirho/src/money_stage_chirho.rs";

    let mut reference_paths_chirho = BTreeSet::new();
    let mut definitions_chirho = BTreeSet::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let raw_source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let source_chirho = production_text_chirho(&raw_source_chirho);
        if !source_chirho.contains(ACTIVATION_SYMBOL_CHIRHO) {
            continue;
        }
        reference_paths_chirho.insert(relative_chirho.clone());
        let ast_chirho = syn::parse_file(&source_chirho).unwrap_or_else(|error_chirho| {
            panic!("reviewed activation inventory must parse {relative_chirho}: {error_chirho}")
        });
        for item_chirho in &ast_chirho.items {
            let Item::Fn(function_chirho) = item_chirho else {
                continue;
            };
            let owner_chirho = function_chirho.sig.ident.to_string();
            if owner_chirho == ACTIVATION_SYMBOL_CHIRHO {
                definitions_chirho.insert((relative_chirho.clone(), owner_chirho.clone()));
            }
        }
    }
    let inventory_chirho = h3_target_inventory_chirho();
    assert!(
        inventory_chirho.unresolved_chirho.is_empty(),
        "H3 capability references must resolve to reviewed target symbols; unresolved forms fail closed: {:?}",
        inventory_chirho.unresolved_chirho
    );
    let call_coordinates_chirho = inventory_chirho
        .call_coordinates_chirho
        .iter()
        .filter(|entry_chirho| entry_chirho.0 .2 == H3_ACTIVATION_TARGET_CHIRHO)
        .map(
            |((file_chirho, owner_chirho, _target_chirho), count_chirho)| {
                (file_chirho.clone(), owner_chirho.clone(), *count_chirho)
            },
        )
        .collect::<BTreeSet<_>>();

    assert_eq!(
        reference_paths_chirho,
        BTreeSet::from([
            ACTIVATION_PATH_CHIRHO.to_owned(),
            HOST_LIB_PATH_CHIRHO.to_owned(),
            MONEY_STAGE_PATH_CHIRHO.to_owned(),
            RESIDENT_OWNER_PATH_CHIRHO.to_owned(),
        ]),
        "reviewed activation references must remain confined to its owner, exports, and offline regenesis"
    );
    assert_eq!(
        definitions_chirho,
        BTreeSet::from([(
            ACTIVATION_PATH_CHIRHO.to_owned(),
            ACTIVATION_SYMBOL_CHIRHO.to_owned(),
        )])
    );
    assert_eq!(
        call_coordinates_chirho,
        BTreeSet::from([(
            MONEY_STAGE_PATH_CHIRHO.to_owned(),
            "provision_money_chirho".to_owned(),
            1,
        )]),
        "the signed activation capsule must have exactly one offline regenesis production caller"
    );
    assert!(
        inventory_chirho.non_call_coordinates_chirho.keys().all(
            |(_file_chirho, _owner_chirho, target_chirho)| {
                target_chirho != H3_ACTIVATION_TARGET_CHIRHO
            }
        ),
        "reviewed activation must not escape as a callback or function value"
    );
}

#[test]
fn offline_activation_authoring_has_one_exact_production_caller_chirho() {
    const AUTHOR_PATH_CHIRHO: &str =
        "crates/ledger-chirho/cairn-ledger-regenesis-chirho/src/money_stage_chirho.rs";
    const REGENESIS_LIB_PATH_CHIRHO: &str =
        "crates/ledger-chirho/cairn-ledger-regenesis-chirho/src/lib.rs";
    const OPERATOR_PREPARE_PATH_CHIRHO: &str =
        "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/operator_prepare_chirho.rs";
    // The second authorized caller: the on-host `ledger-host-activation-author-chirho` CLI verb, which
    // authors the H3 activation authorization from an EXISTING reviewed config/plan (the third
    // authoring artifact the config/plan emission road deliberately stops short of, because its
    // validity window is fixed at 15 minutes). It is pure wiring of the same offline road — it signs,
    // derives, and mints nothing itself — so it widens the confined caller set by exactly one
    // explicit operator porcelain, not the authority.
    const AUTHORING_CLI_PATH_CHIRHO: &str =
        "crates/cairn-cli-chirho/src/cli_helpers_chirho/operations_chirho/ledger_host_author_cli_chirho.rs";
    // The third authorized caller: the `served-llm-dev-bootstrap-chirho` CLI verb, which authors the
    // H3 activation authorization in-process for a LOCAL dev product-door root and then drives the
    // single-node regenesis genesis+mint (`run_ledger_regenesis_chirho`) so the served-LLM card's
    // Hold can succeed at the door. It is dev-only and fail-closed: `refuse_production_posture_chirho`
    // requires a test-kind, and test-kind forces the reserved kind-issuer prefix, so this caller can
    // never author a production activation. Like the CLI verb above, it is pure wiring of the same
    // offline road — it widens the confined caller set by exactly one explicit dev porcelain, not
    // the authority.
    const DEV_BOOTSTRAP_PATH_CHIRHO: &str =
        "crates/services-chirho/cairn-served-llm-dev-bootstrap-chirho/src/lib.rs";

    let inventory_chirho = h3_target_inventory_chirho();
    assert!(
        inventory_chirho.unresolved_chirho.is_empty(),
        "offline activation authoring references must resolve exactly: {:?}",
        inventory_chirho.unresolved_chirho
    );
    let call_coordinates_chirho = inventory_chirho
        .call_coordinates_chirho
        .iter()
        .filter(|entry_chirho| entry_chirho.0 .2 == H3_AUTHOR_TARGET_CHIRHO)
        .map(
            |((file_chirho, owner_chirho, _target_chirho), count_chirho)| {
                (file_chirho.clone(), owner_chirho.clone(), *count_chirho)
            },
        )
        .collect::<BTreeSet<_>>();
    let non_call_coordinates_chirho = inventory_chirho
        .non_call_coordinates_chirho
        .keys()
        .filter(|(_file_chirho, _owner_chirho, target_chirho)| {
            target_chirho == H3_AUTHOR_TARGET_CHIRHO
        })
        .cloned()
        .collect::<BTreeSet<_>>();

    assert_eq!(
        call_coordinates_chirho,
        BTreeSet::from([
            (
                OPERATOR_PREPARE_PATH_CHIRHO.to_owned(),
                "author_credits_demo_inputs_chirho".to_owned(),
                1,
            ),
            (
                AUTHORING_CLI_PATH_CHIRHO.to_owned(),
                "run_ledger_host_activation_author_chirho".to_owned(),
                1,
            ),
            (
                DEV_BOOTSTRAP_PATH_CHIRHO.to_owned(),
                "run_served_llm_dev_bootstrap_chirho".to_owned(),
                1,
            ),
        ]),
        "offline activation authoring must have exactly its three explicit operator callers: the \
         credits-demo input preparation, the on-host activation-author CLI verb, and the served-LLM \
         dev-bootstrap (test-kind-fenced, dev-only)"
    );
    assert!(
        non_call_coordinates_chirho.is_empty(),
        "offline activation authoring must never escape as a callback or function value: {non_call_coordinates_chirho:?}"
    );

    let reference_paths_chirho = workspace_production_rs_files_chirho()
        .into_iter()
        .filter_map(|path_chirho| {
            let raw_source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
            let source_chirho = production_text_chirho(&raw_source_chirho);
            source_chirho
                .contains(H3_AUTHOR_TARGET_CHIRHO)
                .then(|| workspace_relative_chirho(&path_chirho))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        reference_paths_chirho,
        BTreeSet::from([
            AUTHOR_PATH_CHIRHO.to_owned(),
            REGENESIS_LIB_PATH_CHIRHO.to_owned(),
            OPERATOR_PREPARE_PATH_CHIRHO.to_owned(),
            AUTHORING_CLI_PATH_CHIRHO.to_owned(),
            DEV_BOOTSTRAP_PATH_CHIRHO.to_owned(),
        ]),
        "the authoring target must remain confined to its definition, export, and its three explicit \
         operator callers (credits-demo preparation, the activation-author CLI verb, and the \
         served-LLM dev-bootstrap)"
    );
}

#[test]
fn activation_key_custody_stays_in_authoring_and_authorization_precedes_staging_chirho() {
    const MONEY_STAGE_PATH_CHIRHO: &str =
        "crates/ledger-chirho/cairn-ledger-regenesis-chirho/src/money_stage_chirho.rs";
    const ISSUER_PATH_CHIRHO: &str =
        "crates/ledger-chirho/cairn-ledger-regenesis-chirho/src/issuer_chirho.rs";
    const REGENESIS_LIB_PATH_CHIRHO: &str =
        "crates/ledger-chirho/cairn-ledger-regenesis-chirho/src/lib.rs";
    const AUTHOR_FUNCTION_CHIRHO: &str = "author_ledger_regenesis_activation_chirho";
    const PREPARE_FUNCTION_CHIRHO: &str = "prepare_money_stage_chirho";
    const PROVISION_FUNCTION_CHIRHO: &str = "provision_money_chirho";
    const OFFLINE_SIGNER_CHIRHO: &str = "OfflineLedgerActivationSignerChirho";
    const AUTHORIZE_CHIRHO: &str = "authorize_statement_chirho";
    const LOAD_AUTHORIZATION_CHIRHO: &str = "load_verified_activation_authorization_chirho";
    const BEGIN_STAGING_CHIRHO: &str = "begin_staging_chirho";

    let raw_source_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(MONEY_STAGE_PATH_CHIRHO)).unwrap();
    let source_chirho = production_text_chirho(&raw_source_chirho);
    let syntax_chirho = syn::parse_file(&source_chirho).unwrap();
    let request_chirho = syntax_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            Item::Struct(struct_chirho)
                if struct_chirho.ident == "LedgerRegenesisH3aRequestChirho" =>
            {
                Some(struct_chirho)
            }
            _ => None,
        })
        .expect("H3 execution request must exist");
    let request_fields_chirho = request_chirho
        .fields
        .iter()
        .filter_map(|field_chirho| field_chirho.ident.as_ref())
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    assert!(
        !request_fields_chirho.contains("activation_secret_name_chirho"),
        "the mutating H3 execution request must never regain activation-key custody"
    );
    assert!(
        request_fields_chirho.contains("activation_authorization_path_chirho")
            && request_fields_chirho.contains("expected_activation_authorization_digest_chirho"),
        "the mutating H3 execution request must consume the reviewed authorization artifact"
    );

    let author_chirho = activation_boundary_function_chirho(&syntax_chirho, AUTHOR_FUNCTION_CHIRHO);
    let prepare_chirho =
        activation_boundary_function_chirho(&syntax_chirho, PREPARE_FUNCTION_CHIRHO);
    let provision_chirho =
        activation_boundary_function_chirho(&syntax_chirho, PROVISION_FUNCTION_CHIRHO);
    let author_names_chirho = activation_boundary_names_chirho(author_chirho);
    let prepare_names_chirho = activation_boundary_names_chirho(prepare_chirho);
    let provision_names_chirho = activation_boundary_names_chirho(provision_chirho);
    assert_eq!(author_names_chirho.get(OFFLINE_SIGNER_CHIRHO), Some(&1));
    assert_eq!(author_names_chirho.get(AUTHORIZE_CHIRHO), Some(&1));
    for (owner_chirho, names_chirho) in [
        (PREPARE_FUNCTION_CHIRHO, &prepare_names_chirho),
        (PROVISION_FUNCTION_CHIRHO, &provision_names_chirho),
    ] {
        assert!(
            !names_chirho.contains_key(OFFLINE_SIGNER_CHIRHO)
                && !names_chirho.contains_key(AUTHORIZE_CHIRHO)
                && !names_chirho.contains_key("activation_secret_name_chirho"),
            "{owner_chirho} must consume verifier-only authorization and never touch the activation key"
        );
    }
    assert_eq!(
        prepare_names_chirho.get(LOAD_AUTHORIZATION_CHIRHO),
        Some(&1)
    );
    assert_eq!(prepare_names_chirho.get(BEGIN_STAGING_CHIRHO), Some(&1));

    let mut authorization_statement_index_chirho = None;
    let mut begin_staging_statement_index_chirho = None;
    for (index_chirho, statement_chirho) in prepare_chirho.block.stmts.iter().enumerate() {
        match direct_eager_call_name_chirho(statement_chirho).as_deref() {
            Some(LOAD_AUTHORIZATION_CHIRHO) => {
                assert!(authorization_statement_index_chirho.is_none());
                authorization_statement_index_chirho = Some(index_chirho);
            }
            Some(BEGIN_STAGING_CHIRHO) => {
                assert!(begin_staging_statement_index_chirho.is_none());
                begin_staging_statement_index_chirho = Some(index_chirho);
            }
            _ => {}
        }
    }
    assert!(
        authorization_statement_index_chirho
            .zip(begin_staging_statement_index_chirho)
            .is_some_and(|(authorization_chirho, staging_chirho)| {
                authorization_chirho < staging_chirho
            }),
        "exact authorization verification must precede the first staging mutation"
    );

    let mut signer_reference_paths_chirho = BTreeSet::new();
    let mut authorize_reference_paths_chirho = BTreeSet::new();
    let mut authorize_owners_chirho = BTreeSet::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let raw_source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let source_chirho = production_text_chirho(&raw_source_chirho);
        if source_chirho.contains(OFFLINE_SIGNER_CHIRHO) {
            signer_reference_paths_chirho.insert(relative_chirho.clone());
        }
        if source_chirho.contains(AUTHORIZE_CHIRHO) {
            authorize_reference_paths_chirho.insert(relative_chirho.clone());
            let syntax_chirho = syn::parse_file(&source_chirho).unwrap();
            for (owner_chirho, count_chirho) in
                activation_name_owners_chirho(&syntax_chirho, AUTHORIZE_CHIRHO)
            {
                authorize_owners_chirho.insert((
                    relative_chirho.clone(),
                    owner_chirho,
                    count_chirho,
                ));
            }
        }
    }
    let custody_paths_chirho = BTreeSet::from([
        ISSUER_PATH_CHIRHO.to_owned(),
        MONEY_STAGE_PATH_CHIRHO.to_owned(),
    ]);
    assert_eq!(signer_reference_paths_chirho, custody_paths_chirho);
    assert_eq!(authorize_reference_paths_chirho, custody_paths_chirho);
    assert_eq!(
        authorize_owners_chirho,
        BTreeSet::from([(
            MONEY_STAGE_PATH_CHIRHO.to_owned(),
            AUTHOR_FUNCTION_CHIRHO.to_owned(),
            1,
        )]),
        "the offline activation signer may authorize only inside review-artifact authoring"
    );

    let issuer_raw_source_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(ISSUER_PATH_CHIRHO)).unwrap();
    let issuer_source_chirho = production_text_chirho(&issuer_raw_source_chirho);
    let issuer_syntax_chirho = syn::parse_file(&issuer_source_chirho).unwrap();
    let signer_struct_chirho = issuer_syntax_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            Item::Struct(struct_chirho) if struct_chirho.ident == OFFLINE_SIGNER_CHIRHO => {
                Some(struct_chirho)
            }
            _ => None,
        })
        .expect("offline activation signer must remain defined");
    assert!(matches!(
        signer_struct_chirho.vis,
        syn::Visibility::Restricted(ref restricted_chirho)
            if restricted_chirho.path.is_ident("crate")
    ));
    assert!(signer_struct_chirho
        .fields
        .iter()
        .all(|field_chirho| matches!(field_chirho.vis, syn::Visibility::Inherited)));
    let authorize_method_chirho = issuer_syntax_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            Item::Impl(implementation_chirho)
                if matches!(
                    implementation_chirho.self_ty.as_ref(),
                    syn::Type::Path(path_chirho)
                        if path_chirho.path.segments.last().is_some_and(
                            |segment_chirho| segment_chirho.ident == OFFLINE_SIGNER_CHIRHO
                        )
                ) =>
            {
                implementation_chirho
                    .items
                    .iter()
                    .find_map(
                        |implementation_item_chirho| match implementation_item_chirho {
                            syn::ImplItem::Fn(function_chirho)
                                if function_chirho.sig.ident == AUTHORIZE_CHIRHO =>
                            {
                                Some(function_chirho)
                            }
                            _ => None,
                        },
                    )
            }
            _ => None,
        })
        .expect("offline activation authorization method must remain defined");
    assert!(matches!(
        authorize_method_chirho.vis,
        syn::Visibility::Restricted(ref restricted_chirho)
            if restricted_chirho.path.is_ident("crate")
    ));

    let regenesis_lib_raw_source_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(REGENESIS_LIB_PATH_CHIRHO)).unwrap();
    let regenesis_lib_source_chirho = production_text_chirho(&regenesis_lib_raw_source_chirho);
    let regenesis_lib_syntax_chirho = syn::parse_file(&regenesis_lib_source_chirho).unwrap();
    let issuer_module_chirho = regenesis_lib_syntax_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            Item::Mod(module_chirho) if module_chirho.ident == "issuer_chirho" => {
                Some(module_chirho)
            }
            _ => None,
        })
        .expect("offline issuer module must remain declared");
    assert!(
        matches!(issuer_module_chirho.vis, syn::Visibility::Inherited),
        "offline signer custody module must remain private"
    );
}

#[test]
fn resident_genesis_collision_check_has_no_full_object_read_chirho() {
    for path_chirho in [
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/elected_authority_chirho.rs",
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/birth_chirho.rs",
    ] {
        let source_chirho =
            std::fs::read_to_string(workspace_root_chirho().join(path_chirho)).unwrap();
        assert!(
            !source_chirho.contains(".read_all_chirho("),
            "resident host collision checks must reject by bounded length/range reads before full open: {path_chirho}"
        );
        assert!(
            source_chirho.contains(".object_len_chirho(")
                && source_chirho.contains(".read_exact_range_chirho("),
            "resident host lost its bounded exact-genesis textual sentinels: {path_chirho}"
        );
    }
}

#[test]
fn resident_identity_key_guard_catches_alias_and_function_value_creation_chirho() {
    let synthetic_chirho = syn::parse_file(
        "use cairn_signer_chirho::signer_chirho::sign_message_chirho as hidden_chirho;\n\
         use cairn_signer_chirho::signer_chirho::derive_instance_key_chirho as derived_chirho;\n\
         use cairn_signer_chirho::signer_chirho::*;\n\
         fn probe_chirho() {\n\
             let callback_chirho = cairn_signer_chirho::signer_chirho::pubkey_hex_chirho;\n\
             let future_chirho = cairn_signer_chirho::signer_chirho::future_key_creator_chirho;\n\
             let _ignored_chirho = (hidden_chirho, derived_chirho, callback_chirho, future_chirho);\n\
         }",
    )
    .unwrap();
    let mut visitor_chirho = IdentityKeyCallVisitorChirho::default();
    visitor_chirho.visit_file(&synthetic_chirho);
    assert_eq!(
        visitor_chirho.creating_calls_chirho,
        BTreeSet::from([
            "derive_instance_key_chirho".to_owned(),
            "pubkey_hex_chirho".to_owned(),
            "sign_message_chirho".to_owned(),
        ])
    );
    assert_eq!(
        visitor_chirho.signer_targets_chirho,
        BTreeSet::from([
            "derive_instance_key_chirho".to_owned(),
            "future_key_creator_chirho".to_owned(),
            "pubkey_hex_chirho".to_owned(),
            "sign_message_chirho".to_owned(),
        ])
    );
    assert_eq!(
        visitor_chirho.unresolved_signer_targets_chirho,
        BTreeSet::from(["cairn_signer_chirho::signer_chirho::*".to_owned()])
    );
}
