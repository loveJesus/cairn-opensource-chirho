// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The AST classifiers behind the resident-signer surface guard: given a `use` tree or a call name,
//! decide which signer/identity coordinate it names. Split out of the guard file itself, which had
//! grown past the 1,500-line cap -- the guard asserts the property, these decide what the AST means.

use super::super::elected_bridge_guard_tests_chirho::IdentityKeyCallVisitorChirho;
use std::collections::BTreeSet;
use syn::UseTree;

pub(super) fn classify_identity_key_name_chirho(
    name_chirho: String,
    visitor_chirho: &mut IdentityKeyCallVisitorChirho,
) {
    if matches!(
        name_chirho.as_str(),
        "existing_keypair_pubkey_hex_chirho"
            | "sign_message_with_existing_key_chirho"
            | "sign_with_existing_key_possession_chirho"
            | "verify_with_pubkey_chirho"
    ) {
        visitor_chirho.existing_calls_chirho.insert(name_chirho);
    } else if matches!(
        name_chirho.as_str(),
        "sign_message_chirho" | "pubkey_hex_chirho" | "derive_instance_key_chirho"
    ) {
        visitor_chirho.creating_calls_chirho.insert(name_chirho);
    }
}

pub(super) fn classify_signer_path_chirho(
    path_chirho: &syn::Path,
    visitor_chirho: &mut IdentityKeyCallVisitorChirho,
) {
    let path_chirho = path_chirho
        .segments
        .iter()
        .map(|segment_chirho| segment_chirho.ident.to_string())
        .collect::<Vec<_>>()
        .join("::");
    classify_signer_target_path_chirho(&path_chirho, visitor_chirho);
}

pub(super) fn classify_signer_target_path_chirho(
    path_chirho: &str,
    visitor_chirho: &mut IdentityKeyCallVisitorChirho,
) {
    const SIGNER_PREFIX_CHIRHO: &str = "cairn_signer_chirho::signer_chirho::";
    if let Some(target_chirho) = path_chirho.strip_prefix(SIGNER_PREFIX_CHIRHO) {
        if target_chirho.is_empty() || target_chirho == "*" || target_chirho.contains("::") {
            visitor_chirho
                .unresolved_signer_targets_chirho
                .insert(path_chirho.to_owned());
            return;
        }
        visitor_chirho
            .signer_targets_chirho
            .insert(target_chirho.to_owned());
        classify_identity_key_name_chirho(target_chirho.to_owned(), visitor_chirho);
    } else if path_chirho == "cairn_signer_chirho"
        || path_chirho.starts_with("cairn_signer_chirho::")
    {
        visitor_chirho
            .unresolved_signer_targets_chirho
            .insert(path_chirho.to_owned());
    }
}

pub(super) fn collect_use_target_paths_chirho(
    tree_chirho: &UseTree,
    prefix_chirho: &mut Vec<String>,
    targets_chirho: &mut BTreeSet<String>,
) {
    match tree_chirho {
        UseTree::Path(path_chirho) => {
            prefix_chirho.push(path_chirho.ident.to_string());
            collect_use_target_paths_chirho(&path_chirho.tree, prefix_chirho, targets_chirho);
            prefix_chirho.pop();
        }
        UseTree::Name(name_chirho) => {
            let mut target_chirho = prefix_chirho.clone();
            target_chirho.push(name_chirho.ident.to_string());
            targets_chirho.insert(target_chirho.join("::"));
        }
        UseTree::Rename(rename_chirho) => {
            let mut target_chirho = prefix_chirho.clone();
            target_chirho.push(rename_chirho.ident.to_string());
            targets_chirho.insert(target_chirho.join("::"));
        }
        UseTree::Group(group_chirho) => {
            for item_chirho in &group_chirho.items {
                collect_use_target_paths_chirho(item_chirho, prefix_chirho, targets_chirho);
            }
        }
        UseTree::Glob(_glob_chirho) => {
            let mut target_chirho = prefix_chirho.clone();
            target_chirho.push("*".to_owned());
            targets_chirho.insert(target_chirho.join("::"));
        }
    }
}
