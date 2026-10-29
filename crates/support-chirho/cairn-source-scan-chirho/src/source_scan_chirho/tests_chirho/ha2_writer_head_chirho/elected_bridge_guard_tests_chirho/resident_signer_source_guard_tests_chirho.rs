// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Conservative same-source signer regression inventory for the preactivation resident identity.

use super::*;

const RESIDENT_SIGNER_ROOT_CHIRHO: &str = "fn::sign_with_existing_key_possession_chirho";

#[derive(Default)]
struct SignerNodeFactsChirho {
    local_edges_chirho: BTreeSet<String>,
    operations_chirho: BTreeSet<String>,
    unresolved_chirho: BTreeSet<String>,
    forbidden_chirho: BTreeSet<String>,
    bounded_read_to_end_chirho: usize,
}

#[derive(Default)]
struct SignerTransitiveInventoryChirho {
    reachable_nodes_chirho: BTreeSet<String>,
    operations_chirho: BTreeSet<String>,
    unresolved_chirho: BTreeSet<String>,
    forbidden_chirho: BTreeSet<String>,
    bounded_read_to_end_chirho: usize,
}

fn collect_signer_use_aliases_chirho(
    tree_chirho: &UseTree,
    prefix_chirho: &mut Vec<String>,
    aliases_chirho: &mut BTreeMap<String, String>,
    unresolved_chirho: &mut BTreeSet<String>,
) {
    let mut insert_alias_chirho = |alias_chirho: String, target_chirho: String| {
        if aliases_chirho
            .insert(alias_chirho.clone(), target_chirho.clone())
            .is_some_and(|previous_chirho| previous_chirho != target_chirho)
        {
            unresolved_chirho.insert(format!("alias-collision:{alias_chirho}"));
        }
    };
    match tree_chirho {
        UseTree::Path(path_chirho) => {
            prefix_chirho.push(path_chirho.ident.to_string());
            collect_signer_use_aliases_chirho(
                &path_chirho.tree,
                prefix_chirho,
                aliases_chirho,
                unresolved_chirho,
            );
            prefix_chirho.pop();
        }
        UseTree::Name(name_chirho) => {
            let alias_chirho = name_chirho.ident.to_string();
            let mut target_chirho = prefix_chirho.clone();
            target_chirho.push(alias_chirho.clone());
            insert_alias_chirho(alias_chirho, target_chirho.join("::"));
        }
        UseTree::Rename(rename_chirho) => {
            let mut target_chirho = prefix_chirho.clone();
            target_chirho.push(rename_chirho.ident.to_string());
            insert_alias_chirho(rename_chirho.rename.to_string(), target_chirho.join("::"));
        }
        UseTree::Group(group_chirho) => {
            for item_chirho in &group_chirho.items {
                collect_signer_use_aliases_chirho(
                    item_chirho,
                    prefix_chirho,
                    aliases_chirho,
                    unresolved_chirho,
                );
            }
        }
        UseTree::Glob(_) => {
            unresolved_chirho.insert(format!("glob-import:{}", prefix_chirho.join("::")));
        }
    }
}

#[derive(Default)]
struct SignerUseAliasVisitorChirho {
    aliases_chirho: BTreeMap<String, String>,
    unresolved_chirho: BTreeSet<String>,
}

impl<'ast_chirho> Visit<'ast_chirho> for SignerUseAliasVisitorChirho {
    fn visit_item_use(&mut self, use_chirho: &'ast_chirho syn::ItemUse) {
        collect_signer_use_aliases_chirho(
            &use_chirho.tree,
            &mut Vec::new(),
            &mut self.aliases_chirho,
            &mut self.unresolved_chirho,
        );
    }

    fn visit_item_fn(&mut self, _function_chirho: &'ast_chirho syn::ItemFn) {}
}

fn resolve_signer_alias_chirho(
    path_chirho: &syn::Path,
    aliases_chirho: &BTreeMap<String, String>,
) -> Result<String, String> {
    let mut parts_chirho = path_chirho
        .segments
        .iter()
        .map(|segment_chirho| segment_chirho.ident.to_string())
        .collect::<Vec<_>>();
    let mut seen_chirho = BTreeSet::new();
    loop {
        let Some(first_chirho) = parts_chirho.first().cloned() else {
            return Err("empty-path".to_owned());
        };
        let Some(target_chirho) = aliases_chirho.get(&first_chirho) else {
            return Ok(parts_chirho.join("::"));
        };
        if !seen_chirho.insert(first_chirho.clone()) {
            return Err(format!("alias-cycle:{first_chirho}"));
        }
        let mut resolved_chirho = target_chirho
            .split("::")
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        resolved_chirho.extend(parts_chirho.into_iter().skip(1));
        parts_chirho = resolved_chirho;
    }
}

fn signer_path_is_local_chirho(path_chirho: &str, name_chirho: &str) -> bool {
    path_chirho == name_chirho
        || path_chirho == format!("self::{name_chirho}")
        || path_chirho == format!("crate::signer_chirho::{name_chirho}")
        || path_chirho == format!("super::signer_chirho::{name_chirho}")
}

fn signer_operation_is_forbidden_chirho(operation_chirho: &str) -> bool {
    let name_chirho = operation_chirho
        .rsplit("::")
        .next()
        .unwrap_or(operation_chirho);
    matches!(
        name_chirho,
        "create_chirho"
            | "create_dir_chirho"
            | "create_dir_all_chirho"
            | "create_new_chirho"
            | "load_or_create_signing_key_chirho"
            | "set_permissions_chirho"
            | "write_chirho"
            | "write_all_chirho"
            | "write_file_durable_chirho"
            | "write_file_durable_with_mode_chirho"
            | "write_private_signing_key_chirho"
            | "chmod_chirho"
            | "create"
            | "create_dir"
            | "create_dir_all"
            | "create_new"
            | "set_permissions"
            | "write"
            | "write_all"
    )
}

fn signer_simple_receiver_name_chirho(receiver_chirho: &syn::Expr) -> Option<String> {
    let syn::Expr::Path(path_chirho) = receiver_chirho else {
        return None;
    };
    (path_chirho.qself.is_none() && path_chirho.path.segments.len() == 1)
        .then(|| path_chirho.path.segments[0].ident.to_string())
}

fn signer_expected_local_method_receiver_chirho(method_chirho: &str) -> Option<&'static str> {
    match method_chirho {
        "pubkey_hex_chirho" | "sign_message_chirho" => Some("key_chirho"),
        _ => None,
    }
}

struct SignerNodeReferenceVisitorChirho<'a> {
    aliases_chirho: &'a BTreeMap<String, String>,
    free_functions_chirho: &'a BTreeSet<String>,
    method_counts_chirho: &'a BTreeMap<String, usize>,
    facts_chirho: SignerNodeFactsChirho,
}

impl SignerNodeReferenceVisitorChirho<'_> {
    fn classify_path_chirho(&mut self, path_chirho: &syn::Path, function_value_chirho: bool) {
        let resolved_chirho = match resolve_signer_alias_chirho(path_chirho, self.aliases_chirho) {
            Ok(resolved_chirho) => resolved_chirho,
            Err(error_chirho) => {
                self.facts_chirho.unresolved_chirho.insert(error_chirho);
                return;
            }
        };
        let name_chirho = resolved_chirho
            .rsplit("::")
            .next()
            .unwrap_or(&resolved_chirho);
        if self.free_functions_chirho.contains(name_chirho)
            && signer_path_is_local_chirho(&resolved_chirho, name_chirho)
        {
            self.facts_chirho
                .local_edges_chirho
                .insert(format!("fn::{name_chirho}"));
            return;
        }
        if resolved_chirho.ends_with("_chirho") {
            self.facts_chirho
                .unresolved_chirho
                .insert(format!("path:{resolved_chirho}"));
            return;
        }
        if !function_value_chirho {
            self.facts_chirho
                .operations_chirho
                .insert(resolved_chirho.clone());
            if signer_operation_is_forbidden_chirho(&resolved_chirho) {
                self.facts_chirho.forbidden_chirho.insert(resolved_chirho);
            }
        }
    }
}

impl<'ast_chirho> Visit<'ast_chirho> for SignerNodeReferenceVisitorChirho<'_> {
    fn visit_expr_call(&mut self, call_chirho: &'ast_chirho syn::ExprCall) {
        let mut function_chirho = call_chirho.func.as_ref();
        while let syn::Expr::Paren(parenthesized_chirho) = function_chirho {
            function_chirho = &parenthesized_chirho.expr;
        }
        match function_chirho {
            syn::Expr::Path(path_chirho) => {
                self.classify_path_chirho(&path_chirho.path, false);
            }
            _ => {
                self.facts_chirho
                    .unresolved_chirho
                    .insert("indirect-call-expression".to_owned());
                self.visit_expr(function_chirho);
            }
        }
        for argument_chirho in &call_chirho.args {
            self.visit_expr(argument_chirho);
        }
    }

    fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
        let method_chirho = call_chirho.method.to_string();
        match self.method_counts_chirho.get(&method_chirho) {
            Some(1) => {
                let receiver_chirho =
                    signer_simple_receiver_name_chirho(call_chirho.receiver.as_ref());
                if signer_expected_local_method_receiver_chirho(&method_chirho)
                    == receiver_chirho.as_deref()
                {
                    self.facts_chirho
                        .local_edges_chirho
                        .insert(format!("method::{method_chirho}"));
                } else {
                    self.facts_chirho.unresolved_chirho.insert(format!(
                        "method-target:{}::{method_chirho}",
                        receiver_chirho.as_deref().unwrap_or("non-path-receiver")
                    ));
                }
            }
            Some(_) => {
                self.facts_chirho
                    .unresolved_chirho
                    .insert(format!("ambiguous-method:{method_chirho}"));
            }
            None => {
                let operation_chirho = format!("method::{method_chirho}");
                if method_chirho.ends_with("_chirho") {
                    self.facts_chirho
                        .unresolved_chirho
                        .insert(operation_chirho.clone());
                } else {
                    self.facts_chirho
                        .operations_chirho
                        .insert(operation_chirho.clone());
                }
                if signer_operation_is_forbidden_chirho(&operation_chirho) {
                    self.facts_chirho.forbidden_chirho.insert(operation_chirho);
                }
            }
        }
        if method_chirho == "read_to_end" {
            if matches!(
                call_chirho.receiver.as_ref(),
                syn::Expr::MethodCall(inner_chirho)
                    if inner_chirho.method == "take" && inner_chirho.args.len() == 1
            ) {
                self.facts_chirho.bounded_read_to_end_chirho += 1;
            } else {
                self.facts_chirho
                    .unresolved_chirho
                    .insert("unbounded-read-to-end".to_owned());
            }
        }
        self.visit_expr(&call_chirho.receiver);
        for argument_chirho in &call_chirho.args {
            self.visit_expr(argument_chirho);
        }
    }

    fn visit_expr_path(&mut self, path_chirho: &'ast_chirho syn::ExprPath) {
        let raw_name_chirho = path_chirho
            .path
            .segments
            .first()
            .map(|segment_chirho| segment_chirho.ident.to_string());
        if raw_name_chirho
            .as_ref()
            .is_some_and(|name_chirho| self.aliases_chirho.contains_key(name_chirho))
            || path_chirho
                .path
                .segments
                .last()
                .is_some_and(|segment_chirho| {
                    self.free_functions_chirho
                        .contains(&segment_chirho.ident.to_string())
                })
        {
            self.classify_path_chirho(&path_chirho.path, true);
        }
    }

    fn visit_local(&mut self, local_chirho: &'ast_chirho syn::Local) {
        if let syn::Pat::Ident(identifier_chirho) = &local_chirho.pat {
            let name_chirho = identifier_chirho.ident.to_string();
            if self.aliases_chirho.contains_key(&name_chirho)
                || self.free_functions_chirho.contains(&name_chirho)
            {
                self.facts_chirho
                    .unresolved_chirho
                    .insert(format!("local-shadow:{name_chirho}"));
            }
        }
        syn::visit::visit_local(self, local_chirho);
    }

    fn visit_macro(&mut self, macro_chirho: &'ast_chirho syn::Macro) {
        let macro_path_chirho = macro_chirho
            .path
            .segments
            .iter()
            .map(|segment_chirho| segment_chirho.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        if macro_path_chirho.ends_with("_chirho") {
            self.facts_chirho
                .unresolved_chirho
                .insert(format!("macro-path:{macro_path_chirho}"));
        }
        let mut names_chirho = BTreeSet::new();
        signer_macro_identifiers_chirho(macro_chirho.tokens.clone(), &mut names_chirho);
        for name_chirho in names_chirho {
            if self.free_functions_chirho.contains(&name_chirho)
                || signer_operation_is_forbidden_chirho(&name_chirho)
            {
                self.facts_chirho
                    .unresolved_chirho
                    .insert(format!("macro-token:{name_chirho}"));
            }
        }
        syn::visit::visit_path(self, &macro_chirho.path);
    }

    fn visit_item_fn(&mut self, function_chirho: &'ast_chirho syn::ItemFn) {
        self.facts_chirho
            .unresolved_chirho
            .insert(format!("nested-function:{}", function_chirho.sig.ident));
    }
}

fn signer_macro_identifiers_chirho(
    tokens_chirho: proc_macro2::TokenStream,
    names_chirho: &mut BTreeSet<String>,
) {
    for token_chirho in tokens_chirho {
        match token_chirho {
            proc_macro2::TokenTree::Ident(identifier_chirho) => {
                names_chirho.insert(identifier_chirho.to_string());
            }
            proc_macro2::TokenTree::Group(group_chirho) => {
                signer_macro_identifiers_chirho(group_chirho.stream(), names_chirho);
            }
            proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
        }
    }
}

// Conservative same-source regression inventory, not rustc name resolution or a safety boundary.
fn signer_transitive_inventory_chirho(
    source_chirho: &str,
    root_node_chirho: &str,
) -> SignerTransitiveInventoryChirho {
    let syntax_chirho = syn::parse_file(source_chirho).expect("signer source must parse");
    let mut module_uses_chirho = SignerUseAliasVisitorChirho::default();
    for item_chirho in &syntax_chirho.items {
        if let Item::Use(use_chirho) = item_chirho {
            module_uses_chirho.visit_item_use(use_chirho);
        }
    }
    let mut blocks_chirho = BTreeMap::new();
    let mut free_functions_chirho = BTreeSet::new();
    let mut method_counts_chirho = BTreeMap::<String, usize>::new();
    for item_chirho in &syntax_chirho.items {
        match item_chirho {
            Item::Fn(function_chirho) => {
                let name_chirho = function_chirho.sig.ident.to_string();
                free_functions_chirho.insert(name_chirho.clone());
                blocks_chirho
                    .entry(format!("fn::{name_chirho}"))
                    .or_insert_with(Vec::new)
                    .push(function_chirho.block.as_ref());
            }
            Item::Impl(implementation_chirho) => {
                for item_chirho in &implementation_chirho.items {
                    if let syn::ImplItem::Fn(function_chirho) = item_chirho {
                        let name_chirho = function_chirho.sig.ident.to_string();
                        *method_counts_chirho.entry(name_chirho.clone()).or_insert(0) += 1;
                        blocks_chirho
                            .entry(format!("method::{name_chirho}"))
                            .or_insert_with(Vec::new)
                            .push(&function_chirho.block);
                    }
                }
            }
            _ => {}
        }
    }
    let mut node_facts_chirho = BTreeMap::new();
    for (node_chirho, blocks_chirho) in &blocks_chirho {
        let mut local_uses_chirho = SignerUseAliasVisitorChirho::default();
        for block_chirho in blocks_chirho {
            local_uses_chirho.visit_block(block_chirho);
        }
        let mut aliases_chirho = module_uses_chirho.aliases_chirho.clone();
        let mut unresolved_chirho = module_uses_chirho.unresolved_chirho.clone();
        for (alias_chirho, target_chirho) in local_uses_chirho.aliases_chirho {
            if aliases_chirho
                .insert(alias_chirho.clone(), target_chirho.clone())
                .is_some_and(|previous_chirho| previous_chirho != target_chirho)
            {
                unresolved_chirho.insert(format!("alias-shadow:{alias_chirho}"));
            }
        }
        unresolved_chirho.extend(local_uses_chirho.unresolved_chirho);
        let mut visitor_chirho = SignerNodeReferenceVisitorChirho {
            aliases_chirho: &aliases_chirho,
            free_functions_chirho: &free_functions_chirho,
            method_counts_chirho: &method_counts_chirho,
            facts_chirho: SignerNodeFactsChirho {
                unresolved_chirho,
                ..SignerNodeFactsChirho::default()
            },
        };
        for block_chirho in blocks_chirho {
            visitor_chirho.visit_block(block_chirho);
        }
        node_facts_chirho.insert(node_chirho.clone(), visitor_chirho.facts_chirho);
    }

    let mut inventory_chirho = SignerTransitiveInventoryChirho::default();
    let mut pending_chirho = vec![root_node_chirho.to_owned()];
    while let Some(node_chirho) = pending_chirho.pop() {
        if !inventory_chirho
            .reachable_nodes_chirho
            .insert(node_chirho.clone())
        {
            continue;
        }
        let Some(facts_chirho) = node_facts_chirho.get(&node_chirho) else {
            inventory_chirho
                .unresolved_chirho
                .insert(format!("missing-node:{node_chirho}"));
            continue;
        };
        pending_chirho.extend(facts_chirho.local_edges_chirho.iter().cloned());
        inventory_chirho
            .operations_chirho
            .extend(facts_chirho.operations_chirho.iter().cloned());
        inventory_chirho
            .unresolved_chirho
            .extend(facts_chirho.unresolved_chirho.iter().cloned());
        inventory_chirho
            .forbidden_chirho
            .extend(facts_chirho.forbidden_chirho.iter().cloned());
        inventory_chirho.bounded_read_to_end_chirho += facts_chirho.bounded_read_to_end_chirho;
    }
    inventory_chirho
}

#[test]
fn resident_identity_existing_key_signer_regression_is_bounded_and_read_only_chirho() {
    let signer_source_chirho = std::fs::read_to_string(
        workspace_root_chirho()
            .join("crates/support-chirho/cairn-signer-chirho/src/signer_chirho.rs"),
    )
    .unwrap();
    let inventory_chirho =
        signer_transitive_inventory_chirho(&signer_source_chirho, RESIDENT_SIGNER_ROOT_CHIRHO);
    assert_eq!(
        inventory_chirho.reachable_nodes_chirho,
        BTreeSet::from([
            "fn::hex_encode_chirho".to_owned(),
            "fn::inspect_existing_key_root_chirho".to_owned(),
            "fn::load_existing_signing_keypair_chirho".to_owned(),
            "fn::open_existing_file_chirho".to_owned(),
            "fn::pubkey_path_chirho".to_owned(),
            "fn::read_existing_private_seed_chirho".to_owned(),
            "fn::read_existing_public_key_chirho".to_owned(),
            "fn::sign_with_existing_key_possession_chirho".to_owned(),
            "fn::signing_key_path_chirho".to_owned(),
            "fn::validate_existing_key_owners_chirho".to_owned(),
            "fn::validate_existing_public_key_owner_chirho".to_owned(),
            "method::pubkey_hex_chirho".to_owned(),
            "method::sign_message_chirho".to_owned(),
        ]),
        "same-module syntactic signer inventory changed; classify every new wrapper/helper"
    );
    assert!(
        inventory_chirho.unresolved_chirho.is_empty(),
        "same-module syntactic signer inventory left an unresolved reference: {:?}",
        inventory_chirho.unresolved_chirho
    );
    assert!(
        inventory_chirho.forbidden_chirho.is_empty(),
        "same-module syntactic signer inventory reached a custody-mutating spelling: {:?}",
        inventory_chirho.forbidden_chirho
    );
    assert_eq!(
        inventory_chirho.bounded_read_to_end_chirho, 1,
        "the reviewed source must retain one syntactically bounded public-key read_to_end"
    );
    assert_eq!(
        inventory_chirho.operations_chirho,
        BTreeSet::from([
            "Ok".to_owned(),
            "Some".to_owned(),
            "String::from_utf8".to_owned(),
            "String::with_capacity".to_owned(),
            "Vec::with_capacity".to_owned(),
            "ed25519_dalek::SigningKey::from_bytes".to_owned(),
            "method::all".to_owned(),
            "method::as_bytes".to_owned(),
            "method::as_mut".to_owned(),
            "method::contains".to_owned(),
            "method::context".to_owned(),
            "method::custom_flags".to_owned(),
            "method::is_ascii_digit".to_owned(),
            "method::is_dir".to_owned(),
            "method::is_file".to_owned(),
            "method::iter".to_owned(),
            "method::join".to_owned(),
            "method::last".to_owned(),
            "method::len".to_owned(),
            "method::metadata".to_owned(),
            "method::mode".to_owned(),
            "method::nlink".to_owned(),
            "method::open".to_owned(),
            "method::permissions".to_owned(),
            "method::pop".to_owned(),
            "method::push_str".to_owned(),
            "method::read".to_owned(),
            "method::read_exact".to_owned(),
            "method::read_to_end".to_owned(),
            "method::sign".to_owned(),
            "method::take".to_owned(),
            "method::to_bytes".to_owned(),
            "method::uid".to_owned(),
            "method::verifying_key".to_owned(),
            "method::with_context".to_owned(),
            "method::zeroize".to_owned(),
            "std::fs::File::open".to_owned(),
            "std::fs::OpenOptions::new".to_owned(),
            "std::fs::symlink_metadata".to_owned(),
            "zeroize::Zeroizing::new".to_owned(),
        ]),
        "same-module syntactic signer operations changed from the reviewed preactivation shape"
    );
    assert!(
        signer_source_chirho
            .contains(".custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)"),
        "the reviewed source lost its no-follow/nonblocking/close-on-exec textual sentinel"
    );
    assert!(
        signer_source_chirho.contains(".take((PUBLIC_KEY_FILE_MAX_BYTES_CHIRHO + 1) as u64)"),
        "the reviewed source lost its fixed public-key read bound textual sentinel"
    );
    assert_eq!(
        signer_source_chirho
            .matches("metadata_chirho.nlink() != 1")
            .count(),
        2,
        "the reviewed source must retain two single-link custody textual sentinels"
    );
}

#[test]
fn resident_signer_transitive_guard_resolves_wrappers_aliases_and_reexports_chirho() {
    let source_chirho = r#"
        fn bounded_reader_chirho() {}
        use self::bounded_reader_chirho as reader_alias_chirho;
        pub use self::bounded_reader_chirho as reader_reexport_chirho;
        fn wrapper_chirho() {
            let callback_chirho = reader_alias_chirho;
            let _kept_chirho = callback_chirho;
            reader_reexport_chirho();
        }
        fn root_chirho() {
            wrapper_chirho();
        }
    "#;
    let inventory_chirho = signer_transitive_inventory_chirho(source_chirho, "fn::root_chirho");
    assert_eq!(
        inventory_chirho.reachable_nodes_chirho,
        BTreeSet::from([
            "fn::bounded_reader_chirho".to_owned(),
            "fn::root_chirho".to_owned(),
            "fn::wrapper_chirho".to_owned(),
        ])
    );
    assert!(inventory_chirho.unresolved_chirho.is_empty());
}

#[test]
fn resident_signer_transitive_guard_fails_closed_on_unknown_and_mutating_alias_chirho() {
    let unknown_chirho = signer_transitive_inventory_chirho(
        "fn root_chirho() { wrapper_chirho(); }\n\
         fn wrapper_chirho() {\n\
             mystery_chirho();\n\
             object_chirho.mystery_method_chirho();\n\
             mystery_macro_chirho!();\n\
         }",
        "fn::root_chirho",
    );
    assert_eq!(
        unknown_chirho.unresolved_chirho,
        BTreeSet::from([
            "macro-path:mystery_macro_chirho".to_owned(),
            "method::mystery_method_chirho".to_owned(),
            "path:mystery_chirho".to_owned(),
        ])
    );

    let mutating_chirho = signer_transitive_inventory_chirho(
        "use std::fs::write as hidden_write_chirho;\n\
         fn root_chirho() { wrapper_chirho(); }\n\
         fn wrapper_chirho() { hidden_write_chirho(\"x\", b\"x\"); }",
        "fn::root_chirho",
    );
    assert_eq!(
        mutating_chirho.forbidden_chirho,
        BTreeSet::from(["std::fs::write".to_owned()])
    );

    let shadowed_chirho = signer_transitive_inventory_chirho(
        "use self::safe_chirho as callback_chirho;\n\
         fn safe_chirho() {}\n\
         fn root_chirho() {\n\
             let callback_chirho = std::fs::write;\n\
             callback_chirho(\"x\", b\"x\");\n\
         }",
        "fn::root_chirho",
    );
    assert!(
        shadowed_chirho
            .unresolved_chirho
            .contains("local-shadow:callback_chirho"),
        "a local value binding must not silently shadow a resolved function alias"
    );

    let receiver_collision_chirho = signer_transitive_inventory_chirho(
        "struct SigningKeyHandleChirho;\n\
         impl SigningKeyHandleChirho { fn sign_message_chirho(&self) {} }\n\
         fn root_chirho() { other_chirho.sign_message_chirho(); }",
        "fn::root_chirho",
    );
    assert!(
        receiver_collision_chirho
            .unresolved_chirho
            .contains("method-target:other_chirho::sign_message_chirho"),
        "a same-named method on an unclassified receiver must fail closed"
    );
}

#[test]
fn local_append_authority_surface_is_production_bounded_and_classified_chirho() {
    let root_chirho = workspace_root_chirho();
    let owner_path_chirho =
        "crates/support-chirho/cairn-writer-elector-chirho/src/local_append_authority_chirho.rs";
    let elector_lib_chirho =
        root_chirho.join("crates/support-chirho/cairn-writer-elector-chirho/src/lib.rs");
    let elector_lib_source_chirho = std::fs::read_to_string(elector_lib_chirho).unwrap();
    let elector_lib_ast_chirho = syn::parse_file(&elector_lib_source_chirho).unwrap();
    let declarations_chirho = elector_lib_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Mod(module_chirho) if module_chirho.ident == "local_append_authority_chirho" => {
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
        "the sealed local authority handle must remain production compiled"
    );
    let authority_reference_paths_chirho = production_files_chirho
        .iter()
        .filter_map(|path_chirho| {
            let raw_chirho = std::fs::read_to_string(path_chirho).unwrap();
            let source_chirho = production_text_chirho(&raw_chirho);
            (source_chirho.contains("LocalAppendAuthorityHandleChirho")
                || source_chirho.contains("local_append_authority_handle_chirho"))
            .then(|| workspace_relative_chirho(path_chirho))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        authority_reference_paths_chirho,
        BTreeSet::from([
            "crates/ledger-chirho/host-chirho/cairn-ledger-elected-head-transition-chirho/src/lib.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/current_view_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/reconciliation_chirho/current_view_chirho/transfer_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-geo-node-chirho/src/winner_fork_observation_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/activation_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/birth_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/resident_mutation_chirho/authority_open_view_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/resident_mutation_chirho/envelope_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho/post_append_reprobe_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho/migration_chirho/append_barrier_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho/migration_chirho/writer_adoption_chirho/store_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho/recovery_adoption_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho/command_dispatch_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho/winner_handoff_chirho.rs"
                .to_owned(),
            "crates/ledger-chirho/cairn-ledger-regenesis-chirho/src/money_stage_chirho.rs"
                .to_owned(),
            "crates/support-chirho/cairn-writer-elector-chirho/src/lib.rs".to_owned(),
            owner_path_chirho.to_owned(),
            "crates/support-chirho/cairn-writer-elector-chirho/src/raft_elector_chirho.rs"
                .to_owned(),
        ]),
        "the nonconstructible authority handle must remain confined to its owner, elector, export, reviewed activation and adoption, elected-head adapter, resident serving, recovery, and post-append verification actors, current-view and fork-observation verification, page grants, and offline staging"
    );

    let raft_path_chirho = root_chirho
        .join("crates/support-chirho/cairn-writer-elector-chirho/src/raft_elector_chirho.rs");
    let raft_source_chirho = std::fs::read_to_string(raft_path_chirho).unwrap();
    let raft_ast_chirho = syn::parse_file(&raft_source_chirho).unwrap();
    let accessor_declarations_chirho = raft_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Impl(implementation_chirho) => Some(&implementation_chirho.items),
            _ => None,
        })
        .flatten()
        .filter_map(|item_chirho| match item_chirho {
            syn::ImplItem::Fn(function_chirho)
                if function_chirho.sig.ident == "local_append_authority_handle_chirho" =>
            {
                Some((
                    &function_chirho.vis,
                    has_exact_cfg_test_chirho(&function_chirho.attrs),
                ))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(accessor_declarations_chirho.len(), 1);
    assert!(matches!(
        accessor_declarations_chirho[0].0,
        Visibility::Public(_)
    ));
    assert!(!accessor_declarations_chirho[0].1);

    let authority_fields_chirho = raft_ast_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            Item::Struct(struct_chirho) if struct_chirho.ident == "RaftWriterElectorChirho" => {
                Some(
                    struct_chirho
                        .fields
                        .iter()
                        .filter_map(|field_chirho| {
                            let identifier_chirho = field_chirho.ident.as_ref()?.to_string();
                            identifier_chirho
                                .starts_with("local_append_authority_")
                                .then_some((
                                    identifier_chirho,
                                    has_exact_cfg_test_chirho(&field_chirho.attrs),
                                ))
                        })
                        .collect::<BTreeSet<_>>(),
                )
            }
            _ => None,
        })
        .expect("Raft writer elector struct must exist");
    assert_eq!(
        authority_fields_chirho,
        BTreeSet::from([
            ("local_append_authority_handle_chirho".to_owned(), false),
            ("local_append_authority_publisher_chirho".to_owned(), false,),
        ]),
        "the elector-owned publisher and bounded handle must remain production fields"
    );

    let owner_source_chirho = std::fs::read_to_string(root_chirho.join(owner_path_chirho)).unwrap();
    let owner_ast_chirho = syn::parse_file(&owner_source_chirho).unwrap();
    let public_methods_chirho = owner_ast_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            Item::Impl(implementation_chirho) => Some((
                canonical_type_path_chirho(&implementation_chirho.self_ty),
                &implementation_chirho.items,
            )),
            _ => None,
        })
        .flat_map(|(owner_chirho, items_chirho)| {
            items_chirho
                .iter()
                .filter_map(move |item_chirho| match item_chirho {
                    syn::ImplItem::Fn(function_chirho)
                        if matches!(function_chirho.vis, Visibility::Public(_)) =>
                    {
                        Some((owner_chirho.clone(), function_chirho.sig.ident.to_string()))
                    }
                    _ => None,
                })
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        public_methods_chirho,
        BTreeSet::from([
            (
                "LocalAppendAuthorityHandleChirho".to_owned(),
                "consistency_group_chirho".to_owned(),
            ),
            // CF8 tenant migration fence/coordinator, reviewed 2026-08-12. The broad handle can mint
            // two attenuated capabilities. The read handle observes one exact marker lifetime. The
            // control handle can prepare/restore a marker and release only an exact observed owner;
            // it has no append, campaign, tick, deref, accessor, or broad-handle recovery surface.
            (
                "LocalAppendAuthorityHandleChirho".to_owned(),
                "handoff_control_handle_chirho".to_owned(),
            ),
            (
                "LocalAppendAuthorityHandleChirho".to_owned(),
                "handoff_read_handle_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffControlHandleChirho".to_owned(),
                "consistency_group_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffControlHandleChirho".to_owned(),
                "handoff_read_handle_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffControlHandleChirho".to_owned(),
                "node_id_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffControlHandleChirho".to_owned(),
                "release_if_observed_owner_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffControlHandleChirho".to_owned(),
                "restore_handoff_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffControlHandleChirho".to_owned(),
                "try_acquire_observed_handoff_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffControlHandleChirho".to_owned(),
                "try_prepare_handoff_chirho".to_owned(),
            ),
            (
                "LocalAppendAuthorityHandleChirho".to_owned(),
                "node_id_chirho".to_owned(),
            ),
            (
                "LocalAppendAuthorityHandleChirho".to_owned(),
                "restore_handoff_chirho".to_owned(),
            ),
            // GD7 RESUME STEP, ruled (a) by L.J. 2026-08-05 — three REVIEWED additions, classified
            // here rather than admitted by loosening the assertion. This guard fired on them, which
            // is the guard working: new elector surface that narrows a money-authority freeze is
            // exactly what must reach review.
            //
            // * `try_acquire_active_handoff_append_chirho` — the ONE exempt append lane. It admits
            //   only the EXACT active attempt, and its guard type below carries NO `release_chirho`,
            //   so the lane borrows the freeze and can never clear it.
            // * `try_acquire_startup_coordinates_chirho` — a coordinate-only startup seal admitted
            //   with or without a freeze. It yields NO append authority: its distinct guard type
            //   below exposes the same two scalars every other read witness does, and no append path
            //   accepts it. Opening under a freeze never became appending under one.
            // * The two guard types' scalar readers — `process_generation_chirho` and
            //   `published_raft_term_chirho` only, matching every other generation witness here.
            //
            // Any entry beyond this classified set is new surface and must be argued, not added.
            (
                "LocalAppendAuthorityHandleChirho".to_owned(),
                "try_acquire_active_handoff_append_chirho".to_owned(),
            ),
            (
                "LocalAppendAuthorityHandleChirho".to_owned(),
                "try_acquire_chirho".to_owned(),
            ),
            (
                "LocalAppendAuthorityHandleChirho".to_owned(),
                "try_acquire_handoff_chirho".to_owned(),
            ),
            (
                "LocalAppendAuthorityHandleChirho".to_owned(),
                "try_acquire_startup_coordinates_chirho".to_owned(),
            ),
            (
                "LocalActiveHandoffAppendGenerationGuardChirho".to_owned(),
                "process_generation_chirho".to_owned(),
            ),
            (
                "LocalActiveHandoffAppendGenerationGuardChirho".to_owned(),
                "published_raft_term_chirho".to_owned(),
            ),
            (
                "LocalStartupCoordinatesGuardChirho".to_owned(),
                "process_generation_chirho".to_owned(),
            ),
            (
                "LocalStartupCoordinatesGuardChirho".to_owned(),
                "published_raft_term_chirho".to_owned(),
            ),
            (
                "LocalAppendAuthorityHandleChirho".to_owned(),
                "try_acquire_handoff_read_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffReadHandleChirho".to_owned(),
                "require_no_active_handoff_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffReadHandleChirho".to_owned(),
                "try_acquire_handoff_read_chirho".to_owned(),
            ),
            (
                "LocalAppendAuthorityHandleChirho".to_owned(),
                "try_prepare_handoff_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffGenerationGuardChirho".to_owned(),
                "consistency_group_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffGenerationGuardChirho".to_owned(),
                "published_raft_term_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffGenerationGuardChirho".to_owned(),
                "handoff_digest_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffGenerationGuardChirho".to_owned(),
                "node_id_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffGenerationGuardChirho".to_owned(),
                "process_generation_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffGenerationGuardChirho".to_owned(),
                "release_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffPreparationChirho".to_owned(),
                "activate_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffPreparationChirho".to_owned(),
                "consistency_group_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffPreparationChirho".to_owned(),
                "published_raft_term_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffPreparationChirho".to_owned(),
                "handoff_digest_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffPreparationChirho".to_owned(),
                "node_id_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffPreparationChirho".to_owned(),
                "process_generation_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffReadGenerationChirho".to_owned(),
                "consistency_group_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffReadGenerationChirho".to_owned(),
                "handoff_activation_generation_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffReadGenerationChirho".to_owned(),
                "published_raft_term_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffReadGenerationChirho".to_owned(),
                "handoff_digest_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffReadGenerationChirho".to_owned(),
                "node_id_chirho".to_owned(),
            ),
            (
                "LocalAppendHandoffReadGenerationChirho".to_owned(),
                "process_generation_chirho".to_owned(),
            ),
            (
                "LocalLeadershipGenerationGuardChirho".to_owned(),
                "published_raft_term_chirho".to_owned(),
            ),
            (
                "LocalLeadershipGenerationGuardChirho".to_owned(),
                "process_generation_chirho".to_owned(),
            ),
            // Read-only held-observation/clock check; no acquisition or authority minting.
            (
                "LocalLeadershipGenerationGuardChirho".to_owned(),
                "validate_current_chirho".to_owned(),
            ),
        ]),
        "the public local-authority surface must remain the classified generation and handoff API with no caller-created authority, raw append, journal writer, or callback"
    );
}

#[test]
fn elected_fence_helper_inventory_catches_same_file_wrappers_and_aliases_chirho() {
    let fixture_chirho = format!(
        "fn {ELECTED_FENCE_HELPER_CHIRHO}() {{}}\n\
         fn wrapper_chirho() {{ {ELECTED_FENCE_HELPER_CHIRHO}(); }}\n\
         use crate::{ELECTED_FENCE_HELPER_CHIRHO} as alias_chirho;\n\
         const CALLBACK_CHIRHO: fn() = {ELECTED_FENCE_HELPER_CHIRHO};"
    );
    assert_eq!(
        elected_fence_helper_inventory_chirho(&fixture_chirho),
        (1, 3)
    );
}

#[test]
fn elected_bridge_module_reference_inventory_catches_known_indirections_chirho() {
    for fixture_chirho in [
        "fn activate_chirho() { crate::elected_authority_chirho::factory_chirho(); }",
        "use crate::elected_authority_chirho as elected_alias_chirho;",
        "use crate::{elected_authority_chirho as elected_alias_chirho};",
        "pub use crate::elected_authority_chirho::factory_chirho;",
    ] {
        let ast_chirho = syn::parse_file(fixture_chirho).unwrap();
        let mut visitor_chirho = ModuleReferenceVisitorChirho::default();
        visitor_chirho.visit_file(&ast_chirho);
        assert!(
            visitor_chirho.found_chirho,
            "elected bridge reference form escaped the structural inventory: {fixture_chirho}"
        );
    }
}

pub(super) fn has_exact_cfg_test_chirho(attributes_chirho: &[syn::Attribute]) -> bool {
    attributes_chirho.iter().any(|attribute_chirho| {
        attribute_chirho.path().is_ident("cfg")
            && attribute_chirho
                .parse_args::<syn::Path>()
                .is_ok_and(|path_chirho| path_chirho.is_ident("test"))
    })
}

#[derive(Default)]
pub(super) struct ModuleReferenceVisitorChirho {
    pub(super) found_chirho: bool,
}

impl<'ast_chirho> Visit<'ast_chirho> for ModuleReferenceVisitorChirho {
    fn visit_path(&mut self, path_chirho: &'ast_chirho syn::Path) {
        if path_chirho
            .segments
            .iter()
            .any(|segment_chirho| segment_chirho.ident == "elected_authority_chirho")
        {
            self.found_chirho = true;
        }
        syn::visit::visit_path(self, path_chirho);
    }

    fn visit_use_tree(&mut self, tree_chirho: &'ast_chirho UseTree) {
        if use_tree_names_module_chirho(tree_chirho) {
            self.found_chirho = true;
        }
        syn::visit::visit_use_tree(self, tree_chirho);
    }
}

fn use_tree_names_module_chirho(tree_chirho: &UseTree) -> bool {
    match tree_chirho {
        UseTree::Path(path_chirho) => {
            path_chirho.ident == "elected_authority_chirho"
                || use_tree_names_module_chirho(&path_chirho.tree)
        }
        UseTree::Name(name_chirho) => name_chirho.ident == "elected_authority_chirho",
        UseTree::Rename(rename_chirho) => rename_chirho.ident == "elected_authority_chirho",
        UseTree::Group(group_chirho) => group_chirho.items.iter().any(use_tree_names_module_chirho),
        UseTree::Glob(_) => false,
    }
}

pub(super) fn visibility_is_crate_chirho(visibility_chirho: &Visibility) -> bool {
    matches!(
        visibility_chirho,
        Visibility::Restricted(restricted_chirho)
            if restricted_chirho.path.segments.len() == 1
                && restricted_chirho.path.segments[0].ident == "crate"
    )
}

pub(super) fn canonical_type_path_chirho(type_chirho: &Type) -> String {
    match type_chirho {
        Type::Reference(reference_chirho) => canonical_type_path_chirho(&reference_chirho.elem),
        Type::Path(path_chirho) if path_chirho.qself.is_none() => path_chirho
            .path
            .segments
            .iter()
            .map(|segment_chirho| {
                let arguments_chirho = match &segment_chirho.arguments {
                    PathArguments::None => String::new(),
                    PathArguments::AngleBracketed(arguments_chirho)
                        if arguments_chirho.args.iter().all(|argument_chirho| {
                            matches!(argument_chirho, GenericArgument::Lifetime(_))
                        }) =>
                    {
                        String::new()
                    }
                    PathArguments::AngleBracketed(arguments_chirho)
                        if arguments_chirho.args.iter().all(|argument_chirho| {
                            matches!(argument_chirho, GenericArgument::Type(_))
                        }) =>
                    {
                        let inner_chirho = arguments_chirho
                            .args
                            .iter()
                            .map(|argument_chirho| match argument_chirho {
                                GenericArgument::Type(type_chirho) => {
                                    canonical_type_path_chirho(type_chirho)
                                }
                                _ => unreachable!("all arguments were checked as types"),
                            })
                            .collect::<Vec<_>>()
                            .join(",");
                        format!("<{inner_chirho}>")
                    }
                    _ => panic!("elected port target has unreviewed type arguments"),
                };
                format!("{}{arguments_chirho}", segment_chirho.ident)
            })
            .collect::<Vec<_>>()
            .join("::"),
        _ => panic!("elected port type is not one exact concrete path reference"),
    }
}

#[derive(Default)]
struct ElectedFenceReferenceVisitorChirho {
    references_chirho: usize,
}

impl<'ast_chirho> Visit<'ast_chirho> for ElectedFenceReferenceVisitorChirho {
    fn visit_ident(&mut self, identifier_chirho: &'ast_chirho proc_macro2::Ident) {
        if identifier_chirho == ELECTED_FENCE_HELPER_CHIRHO {
            self.references_chirho += 1;
        }
    }

    fn visit_macro(&mut self, macro_chirho: &'ast_chirho syn::Macro) {
        count_identifier_tokens_chirho(
            macro_chirho.tokens.clone(),
            ELECTED_FENCE_HELPER_CHIRHO,
            &mut self.references_chirho,
        );
        syn::visit::visit_path(self, &macro_chirho.path);
    }
}

pub(super) fn elected_fence_helper_inventory_chirho(source_chirho: &str) -> (usize, usize) {
    let ast_chirho = syn::parse_file(source_chirho)
        .expect("elected fence production-reference inventory must parse");
    let mut definitions_chirho = 0;
    let mut visitor_chirho = ElectedFenceReferenceVisitorChirho::default();
    for item_chirho in &ast_chirho.items {
        if matches!(
            item_chirho,
            Item::Fn(function_chirho) if function_chirho.sig.ident == ELECTED_FENCE_HELPER_CHIRHO
        ) {
            definitions_chirho += 1;
        } else {
            visitor_chirho.visit_item(item_chirho);
        }
    }
    (definitions_chirho, visitor_chirho.references_chirho)
}

fn count_identifier_tokens_chirho(
    tokens_chirho: proc_macro2::TokenStream,
    target_chirho: &str,
    count_chirho: &mut usize,
) {
    for token_chirho in tokens_chirho {
        match token_chirho {
            proc_macro2::TokenTree::Ident(identifier_chirho)
                if identifier_chirho == target_chirho =>
            {
                *count_chirho += 1;
            }
            proc_macro2::TokenTree::Group(group_chirho) => {
                count_identifier_tokens_chirho(group_chirho.stream(), target_chirho, count_chirho);
            }
            _ => {}
        }
    }
}
