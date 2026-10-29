// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Conservative target resolution for the H3 resident capability boundary.
//!
//! This extracts the resolve-over-spelling and fail-closed shape proven by the R6e posting-family
//! guard. It is intentionally not a rustc name resolver: known module, function, and resident-type
//! imports collapse to reviewed targets, while a family-named reference that cannot be resolved is
//! returned as evidence that the production guard must reject.

use super::*;
use proc_macro2::TokenTree;
use std::collections::{BTreeMap, BTreeSet};
use syn::visit::Visit;
use syn::{Expr, FnArg, ImplItem, Item, Pat, Stmt, Type, UseTree, Visibility};

pub(super) type H3TargetCoordinateChirho = (String, String, String);
pub(super) type H3UnresolvedReferenceChirho = (String, String, String);

pub(super) const H3_ACTIVATION_TARGET_CHIRHO: &str = "activate_reviewed_h3_chirho";
pub(super) const H3_AUTHOR_TARGET_CHIRHO: &str = "author_ledger_regenesis_activation_chirho";
pub(super) const H3_BIRTH_TARGET_CHIRHO: &str = "create_bound_preactivation_chirho";
pub(super) const H3_BIRTH_PERMIT_TARGET_CHIRHO: &str = "for_reviewed_activation_chirho";
pub(super) const H3_ADOPTION_BIRTH_PERMIT_TARGET_CHIRHO: &str = "for_reviewed_adoption_chirho";
pub(super) const H3_APPEND_TARGET_CHIRHO: &str = "append_preactivation_chirho";

const H3_TARGET_FAMILY_CHIRHO: [&str; 6] = [
    H3_ACTIVATION_TARGET_CHIRHO,
    H3_AUTHOR_TARGET_CHIRHO,
    H3_BIRTH_TARGET_CHIRHO,
    H3_BIRTH_PERMIT_TARGET_CHIRHO,
    H3_ADOPTION_BIRTH_PERMIT_TARGET_CHIRHO,
    H3_APPEND_TARGET_CHIRHO,
];
const RESIDENT_AUTHORITY_TYPE_CHIRHO: &str = "ResidentLedgerAuthorityChirho";
const RESIDENT_BIRTH_PERMIT_TYPE_CHIRHO: &str = "ResidentLedgerBirthPermitChirho";
const HOST_CRATE_PATH_CHIRHO: &str = "cairn_ledger_host_chirho";
const REGENESIS_CRATE_PATH_CHIRHO: &str = "cairn_ledger_regenesis_chirho";
const RESIDENT_AUTHORITY_MODULE_CHIRHO: &str = "resident_authority_chirho";
const ACTIVATION_MODULE_CHIRHO: &str = "activation_chirho";
const BIRTH_MODULE_CHIRHO: &str = "birth_chirho";
const MONEY_STAGE_MODULE_CHIRHO: &str = "money_stage_chirho";

#[derive(Clone, Debug, Default)]
struct H3ImportResolutionChirho {
    target_aliases_chirho: BTreeMap<String, String>,
    resident_authority_aliases_chirho: BTreeSet<String>,
    birth_permit_aliases_chirho: BTreeSet<String>,
    host_module_aliases_chirho: BTreeSet<String>,
    regenesis_module_aliases_chirho: BTreeSet<String>,
    host_glob_chirho: bool,
    regenesis_glob_chirho: bool,
    unresolved_chirho: BTreeSet<String>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct H3TargetInventoryChirho {
    pub(super) coordinates_chirho: BTreeMap<H3TargetCoordinateChirho, usize>,
    pub(super) call_coordinates_chirho: BTreeMap<H3TargetCoordinateChirho, usize>,
    pub(super) non_call_coordinates_chirho: BTreeMap<H3TargetCoordinateChirho, usize>,
    pub(super) unresolved_chirho: BTreeSet<H3UnresolvedReferenceChirho>,
}

fn ident_name_chirho(ident_chirho: &syn::Ident) -> String {
    let rendered_chirho = ident_chirho.to_string();
    rendered_chirho
        .strip_prefix("r#")
        .unwrap_or(&rendered_chirho)
        .to_owned()
}

fn path_segments_chirho(path_chirho: &syn::Path) -> Vec<String> {
    path_chirho
        .segments
        .iter()
        .map(|segment_chirho| ident_name_chirho(&segment_chirho.ident))
        .collect()
}

fn source_is_host_crate_chirho(file_chirho: &str) -> bool {
    file_chirho.starts_with("crates/ledger-chirho/cairn-ledger-host-chirho/")
}

fn source_is_regenesis_crate_chirho(file_chirho: &str) -> bool {
    file_chirho.starts_with("crates/ledger-chirho/cairn-ledger-regenesis-chirho/")
}

fn target_family_contains_chirho(name_chirho: &str) -> bool {
    H3_TARGET_FAMILY_CHIRHO.contains(&name_chirho)
}

fn is_host_module_segment_chirho(part_chirho: &str) -> bool {
    matches!(
        part_chirho,
        RESIDENT_AUTHORITY_MODULE_CHIRHO | ACTIVATION_MODULE_CHIRHO | BIRTH_MODULE_CHIRHO
    )
}

fn path_names_host_module_chirho(parts_chirho: &[String]) -> bool {
    parts_chirho
        .split_first()
        .is_some_and(|(first_chirho, rest_chirho)| {
            first_chirho == HOST_CRATE_PATH_CHIRHO
                && rest_chirho
                    .iter()
                    .all(|part_chirho| is_host_module_segment_chirho(part_chirho))
        })
}

fn path_names_regenesis_module_chirho(parts_chirho: &[String]) -> bool {
    parts_chirho
        .split_first()
        .is_some_and(|(first_chirho, rest_chirho)| {
            first_chirho == REGENESIS_CRATE_PATH_CHIRHO
                && rest_chirho
                    .iter()
                    .all(|part_chirho| part_chirho == MONEY_STAGE_MODULE_CHIRHO)
        })
}

fn path_is_local_host_module_chirho(parts_chirho: &[String]) -> bool {
    if parts_chirho.is_empty() {
        return true;
    }
    let first_non_relative_chirho = parts_chirho
        .iter()
        .position(|part_chirho| !matches!(part_chirho.as_str(), "crate" | "self" | "super"))
        .unwrap_or(parts_chirho.len());
    parts_chirho[..first_non_relative_chirho]
        .iter()
        .all(|part_chirho| matches!(part_chirho.as_str(), "crate" | "self" | "super"))
        && parts_chirho[first_non_relative_chirho..]
            .iter()
            .all(|part_chirho| is_host_module_segment_chirho(part_chirho))
}

fn path_is_local_regenesis_module_chirho(parts_chirho: &[String]) -> bool {
    if parts_chirho.is_empty() {
        return true;
    }
    let first_non_relative_chirho = parts_chirho
        .iter()
        .position(|part_chirho| !matches!(part_chirho.as_str(), "crate" | "self" | "super"))
        .unwrap_or(parts_chirho.len());
    parts_chirho[..first_non_relative_chirho]
        .iter()
        .all(|part_chirho| matches!(part_chirho.as_str(), "crate" | "self" | "super"))
        && parts_chirho[first_non_relative_chirho..]
            .iter()
            .all(|part_chirho| part_chirho == MONEY_STAGE_MODULE_CHIRHO)
}

fn import_prefix_resolves_host_chirho(file_chirho: &str, prefix_chirho: &[String]) -> bool {
    path_names_host_module_chirho(prefix_chirho)
        || (source_is_host_crate_chirho(file_chirho)
            && path_is_local_host_module_chirho(prefix_chirho))
}

fn import_prefix_resolves_regenesis_chirho(file_chirho: &str, prefix_chirho: &[String]) -> bool {
    path_names_regenesis_module_chirho(prefix_chirho)
        || (source_is_regenesis_crate_chirho(file_chirho)
            && path_is_local_regenesis_module_chirho(prefix_chirho))
}

fn import_prefix_resolves_target_chirho(
    file_chirho: &str,
    prefix_chirho: &[String],
    target_chirho: &str,
) -> bool {
    if target_chirho == H3_AUTHOR_TARGET_CHIRHO {
        import_prefix_resolves_regenesis_chirho(file_chirho, prefix_chirho)
    } else {
        import_prefix_resolves_host_chirho(file_chirho, prefix_chirho)
    }
}

fn collect_use_leaves_chirho(
    tree_chirho: &UseTree,
    prefix_chirho: &mut Vec<String>,
    leaves_chirho: &mut Vec<(Vec<String>, String, bool)>,
) {
    match tree_chirho {
        UseTree::Path(path_chirho) => {
            prefix_chirho.push(ident_name_chirho(&path_chirho.ident));
            collect_use_leaves_chirho(&path_chirho.tree, prefix_chirho, leaves_chirho);
            prefix_chirho.pop();
        }
        UseTree::Name(name_chirho) => {
            let mut target_chirho = prefix_chirho.clone();
            let name_chirho = ident_name_chirho(&name_chirho.ident);
            target_chirho.push(name_chirho.clone());
            leaves_chirho.push((target_chirho, name_chirho, false));
        }
        UseTree::Rename(rename_chirho) => {
            let mut target_chirho = prefix_chirho.clone();
            let renamed_target_chirho = ident_name_chirho(&rename_chirho.ident);
            if renamed_target_chirho != "self" {
                target_chirho.push(renamed_target_chirho);
            }
            leaves_chirho.push((
                target_chirho,
                ident_name_chirho(&rename_chirho.rename),
                false,
            ));
        }
        UseTree::Glob(_) => {
            leaves_chirho.push((prefix_chirho.clone(), "*".to_owned(), true));
        }
        UseTree::Group(group_chirho) => {
            for item_chirho in &group_chirho.items {
                collect_use_leaves_chirho(item_chirho, prefix_chirho, leaves_chirho);
            }
        }
    }
}

fn insert_alias_chirho(
    aliases_chirho: &mut BTreeMap<String, String>,
    unresolved_chirho: &mut BTreeSet<String>,
    alias_chirho: String,
    target_chirho: String,
) {
    if aliases_chirho
        .get(&alias_chirho)
        .is_some_and(|prior_chirho| prior_chirho != &target_chirho)
    {
        unresolved_chirho.insert(format!("alias-collision:{alias_chirho}"));
        return;
    }
    aliases_chirho.insert(alias_chirho, target_chirho);
}

fn apply_use_chirho(
    file_chirho: &str,
    use_chirho: &syn::ItemUse,
    imports_chirho: &mut H3ImportResolutionChirho,
) {
    let mut leaves_chirho = Vec::new();
    collect_use_leaves_chirho(&use_chirho.tree, &mut Vec::new(), &mut leaves_chirho);
    for (target_chirho, alias_chirho, glob_chirho) in leaves_chirho {
        if glob_chirho {
            if import_prefix_resolves_host_chirho(file_chirho, &target_chirho) {
                imports_chirho.host_glob_chirho = true;
            } else if import_prefix_resolves_regenesis_chirho(file_chirho, &target_chirho) {
                imports_chirho.regenesis_glob_chirho = true;
            } else if target_chirho.iter().any(|part_chirho| {
                target_family_contains_chirho(part_chirho)
                    || part_chirho == RESIDENT_AUTHORITY_TYPE_CHIRHO
            }) {
                imports_chirho
                    .unresolved_chirho
                    .insert(format!("glob-import:{}", target_chirho.join("::")));
            }
            continue;
        }
        let Some(leaf_chirho) = target_chirho.last() else {
            continue;
        };
        let prefix_chirho = &target_chirho[..target_chirho.len().saturating_sub(1)];
        if target_family_contains_chirho(leaf_chirho) {
            if import_prefix_resolves_target_chirho(file_chirho, prefix_chirho, leaf_chirho) {
                if !matches!(use_chirho.vis, Visibility::Inherited) && alias_chirho != *leaf_chirho
                {
                    imports_chirho.unresolved_chirho.insert(format!(
                        "renamed-public-target:{}->{alias_chirho}",
                        target_chirho.join("::")
                    ));
                    continue;
                }
                insert_alias_chirho(
                    &mut imports_chirho.target_aliases_chirho,
                    &mut imports_chirho.unresolved_chirho,
                    alias_chirho,
                    leaf_chirho.clone(),
                );
            } else {
                imports_chirho
                    .unresolved_chirho
                    .insert(format!("import-target:{}", target_chirho.join("::")));
            }
        } else if leaf_chirho == RESIDENT_AUTHORITY_TYPE_CHIRHO {
            if import_prefix_resolves_host_chirho(file_chirho, prefix_chirho) {
                if !matches!(use_chirho.vis, Visibility::Inherited) && alias_chirho != *leaf_chirho
                {
                    imports_chirho.unresolved_chirho.insert(format!(
                        "renamed-public-resident-type:{}->{alias_chirho}",
                        target_chirho.join("::")
                    ));
                    continue;
                }
                imports_chirho
                    .resident_authority_aliases_chirho
                    .insert(alias_chirho);
            } else {
                imports_chirho
                    .unresolved_chirho
                    .insert(format!("import-resident-type:{}", target_chirho.join("::")));
            }
        } else if leaf_chirho == RESIDENT_BIRTH_PERMIT_TYPE_CHIRHO {
            if import_prefix_resolves_host_chirho(file_chirho, prefix_chirho) {
                if !matches!(use_chirho.vis, Visibility::Inherited) && alias_chirho != *leaf_chirho
                {
                    imports_chirho.unresolved_chirho.insert(format!(
                        "renamed-public-birth-permit-type:{}->{alias_chirho}",
                        target_chirho.join("::")
                    ));
                    continue;
                }
                imports_chirho
                    .birth_permit_aliases_chirho
                    .insert(alias_chirho);
            } else {
                imports_chirho.unresolved_chirho.insert(format!(
                    "import-birth-permit-type:{}",
                    target_chirho.join("::")
                ));
            }
        } else if path_names_host_module_chirho(&target_chirho)
            || (source_is_host_crate_chirho(file_chirho)
                && path_is_local_host_module_chirho(&target_chirho))
        {
            if !matches!(use_chirho.vis, Visibility::Inherited) && alias_chirho != *leaf_chirho {
                imports_chirho.unresolved_chirho.insert(format!(
                    "renamed-public-host-module:{}->{alias_chirho}",
                    target_chirho.join("::")
                ));
                continue;
            }
            imports_chirho
                .host_module_aliases_chirho
                .insert(alias_chirho);
        } else if path_names_regenesis_module_chirho(&target_chirho)
            || (source_is_regenesis_crate_chirho(file_chirho)
                && path_is_local_regenesis_module_chirho(&target_chirho))
        {
            if !matches!(use_chirho.vis, Visibility::Inherited) && alias_chirho != *leaf_chirho {
                imports_chirho.unresolved_chirho.insert(format!(
                    "renamed-public-regenesis-module:{}->{alias_chirho}",
                    target_chirho.join("::")
                ));
                continue;
            }
            imports_chirho
                .regenesis_module_aliases_chirho
                .insert(alias_chirho);
        }
    }
}

fn module_imports_for_syntax_chirho(
    file_chirho: &str,
    syntax_chirho: &syn::File,
) -> H3ImportResolutionChirho {
    let mut imports_chirho = H3ImportResolutionChirho::default();
    for item_chirho in &syntax_chirho.items {
        if let Item::Use(use_chirho) = item_chirho {
            apply_use_chirho(file_chirho, use_chirho, &mut imports_chirho);
        }
    }
    imports_chirho
}

fn imports_for_block_chirho(
    file_chirho: &str,
    block_chirho: &syn::Block,
    module_imports_chirho: &H3ImportResolutionChirho,
) -> H3ImportResolutionChirho {
    let mut imports_chirho = module_imports_chirho.clone();
    for statement_chirho in &block_chirho.stmts {
        if let Stmt::Item(Item::Use(use_chirho)) = statement_chirho {
            apply_use_chirho(file_chirho, use_chirho, &mut imports_chirho);
        }
    }
    imports_chirho
}

fn path_prefix_resolves_host_chirho(
    file_chirho: &str,
    prefix_chirho: &[String],
    imports_chirho: &H3ImportResolutionChirho,
) -> bool {
    path_names_host_module_chirho(prefix_chirho)
        || prefix_chirho
            .split_first()
            .is_some_and(|(first_chirho, rest_chirho)| {
                imports_chirho
                    .host_module_aliases_chirho
                    .contains(first_chirho)
                    && rest_chirho
                        .iter()
                        .all(|part_chirho| is_host_module_segment_chirho(part_chirho))
            })
        || (source_is_host_crate_chirho(file_chirho)
            && path_is_local_host_module_chirho(prefix_chirho))
}

fn path_prefix_resolves_regenesis_chirho(
    file_chirho: &str,
    prefix_chirho: &[String],
    imports_chirho: &H3ImportResolutionChirho,
) -> bool {
    path_names_regenesis_module_chirho(prefix_chirho)
        || prefix_chirho
            .split_first()
            .is_some_and(|(first_chirho, rest_chirho)| {
                imports_chirho
                    .regenesis_module_aliases_chirho
                    .contains(first_chirho)
                    && rest_chirho
                        .iter()
                        .all(|part_chirho| part_chirho == MONEY_STAGE_MODULE_CHIRHO)
            })
        || (source_is_regenesis_crate_chirho(file_chirho)
            && path_is_local_regenesis_module_chirho(prefix_chirho))
}

fn type_path_resolves_chirho(
    path_chirho: &syn::Path,
    aliases_chirho: &BTreeSet<String>,
    canonical_chirho: &str,
    file_chirho: &str,
    imports_chirho: &H3ImportResolutionChirho,
) -> bool {
    let parts_chirho = path_segments_chirho(path_chirho);
    let Some(last_chirho) = parts_chirho.last() else {
        return false;
    };
    if aliases_chirho.contains(last_chirho) {
        return true;
    }
    if last_chirho != canonical_chirho {
        return false;
    }
    parts_chirho.len() == 1
        && (source_is_host_crate_chirho(file_chirho) || imports_chirho.host_glob_chirho)
        || parts_chirho.len() > 1
            && path_prefix_resolves_host_chirho(
                file_chirho,
                &parts_chirho[..parts_chirho.len() - 1],
                imports_chirho,
            )
}

fn type_is_resident_authority_chirho(
    type_chirho: &Type,
    file_chirho: &str,
    imports_chirho: &H3ImportResolutionChirho,
) -> bool {
    match type_chirho {
        Type::Group(group_chirho) => {
            type_is_resident_authority_chirho(&group_chirho.elem, file_chirho, imports_chirho)
        }
        Type::Paren(paren_chirho) => {
            type_is_resident_authority_chirho(&paren_chirho.elem, file_chirho, imports_chirho)
        }
        Type::Path(path_chirho) => type_path_resolves_chirho(
            &path_chirho.path,
            &imports_chirho.resident_authority_aliases_chirho,
            RESIDENT_AUTHORITY_TYPE_CHIRHO,
            file_chirho,
            imports_chirho,
        ),
        Type::Reference(reference_chirho) => {
            type_is_resident_authority_chirho(&reference_chirho.elem, file_chirho, imports_chirho)
        }
        _ => false,
    }
}

fn path_resolves_associated_owner_chirho(
    prefix_chirho: &[String],
    owner_type_chirho: &str,
    owner_aliases_chirho: &BTreeSet<String>,
    file_chirho: &str,
    imports_chirho: &H3ImportResolutionChirho,
    owner_is_resident_chirho: bool,
) -> bool {
    let Some(last_chirho) = prefix_chirho.last() else {
        return false;
    };
    if last_chirho == "Self" {
        return owner_is_resident_chirho;
    }
    if owner_aliases_chirho.contains(last_chirho) {
        return true;
    }
    if last_chirho != owner_type_chirho {
        return false;
    }
    prefix_chirho.len() == 1
        && (source_is_host_crate_chirho(file_chirho) || imports_chirho.host_glob_chirho)
        || prefix_chirho.len() > 1
            && path_prefix_resolves_host_chirho(
                file_chirho,
                &prefix_chirho[..prefix_chirho.len() - 1],
                imports_chirho,
            )
}

fn resolve_target_path_chirho(
    path_chirho: &syn::Path,
    file_chirho: &str,
    imports_chirho: &H3ImportResolutionChirho,
    owner_is_resident_chirho: bool,
) -> Result<Option<String>, String> {
    let parts_chirho = path_segments_chirho(path_chirho);
    let Some(last_chirho) = parts_chirho.last() else {
        return Ok(None);
    };
    if let Some(target_chirho) = imports_chirho.target_aliases_chirho.get(last_chirho) {
        return Ok(Some(target_chirho.clone()));
    }
    if !target_family_contains_chirho(last_chirho) {
        return Ok(None);
    }
    let prefix_chirho = &parts_chirho[..parts_chirho.len().saturating_sub(1)];
    let resolved_chirho = match last_chirho.as_str() {
        H3_ACTIVATION_TARGET_CHIRHO => {
            (prefix_chirho.is_empty() && imports_chirho.host_glob_chirho)
                || path_prefix_resolves_host_chirho(file_chirho, prefix_chirho, imports_chirho)
        }
        H3_AUTHOR_TARGET_CHIRHO => {
            (prefix_chirho.is_empty()
                && (source_is_regenesis_crate_chirho(file_chirho)
                    || imports_chirho.regenesis_glob_chirho))
                || path_prefix_resolves_regenesis_chirho(file_chirho, prefix_chirho, imports_chirho)
        }
        H3_BIRTH_TARGET_CHIRHO | H3_APPEND_TARGET_CHIRHO => path_resolves_associated_owner_chirho(
            prefix_chirho,
            RESIDENT_AUTHORITY_TYPE_CHIRHO,
            &imports_chirho.resident_authority_aliases_chirho,
            file_chirho,
            imports_chirho,
            owner_is_resident_chirho,
        ),
        H3_BIRTH_PERMIT_TARGET_CHIRHO | H3_ADOPTION_BIRTH_PERMIT_TARGET_CHIRHO => {
            path_resolves_associated_owner_chirho(
                prefix_chirho,
                RESIDENT_BIRTH_PERMIT_TYPE_CHIRHO,
                &imports_chirho.birth_permit_aliases_chirho,
                file_chirho,
                imports_chirho,
                false,
            )
        }
        _ => false,
    };
    if resolved_chirho {
        Ok(Some(last_chirho.clone()))
    } else {
        Err(format!("path:{}", parts_chirho.join("::")))
    }
}

fn pattern_names_chirho(pattern_chirho: &Pat, names_chirho: &mut BTreeSet<String>) {
    match pattern_chirho {
        Pat::Ident(ident_chirho) => {
            names_chirho.insert(ident_name_chirho(&ident_chirho.ident));
            if let Some((_at_chirho, nested_chirho)) = &ident_chirho.subpat {
                pattern_names_chirho(nested_chirho, names_chirho);
            }
        }
        Pat::Reference(reference_chirho) => {
            pattern_names_chirho(&reference_chirho.pat, names_chirho)
        }
        Pat::Tuple(tuple_chirho) => {
            for element_chirho in &tuple_chirho.elems {
                pattern_names_chirho(element_chirho, names_chirho);
            }
        }
        Pat::TupleStruct(tuple_chirho) => {
            for element_chirho in &tuple_chirho.elems {
                pattern_names_chirho(element_chirho, names_chirho);
            }
        }
        Pat::Type(type_chirho) => pattern_names_chirho(&type_chirho.pat, names_chirho),
        _ => {}
    }
}

fn token_identifiers_chirho(
    stream_chirho: proc_macro2::TokenStream,
    identifiers_chirho: &mut BTreeSet<String>,
) {
    for token_chirho in stream_chirho {
        match token_chirho {
            TokenTree::Ident(ident_chirho) => {
                identifiers_chirho.insert(ident_name_chirho(&ident_chirho));
            }
            TokenTree::Group(group_chirho) => {
                token_identifiers_chirho(group_chirho.stream(), identifiers_chirho);
            }
            TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
}

fn macro_target_evidence_chirho(
    macro_chirho: &syn::Macro,
    imports_chirho: &H3ImportResolutionChirho,
) -> BTreeSet<String> {
    let mut identifiers_chirho = BTreeSet::new();
    token_identifiers_chirho(macro_chirho.tokens.clone(), &mut identifiers_chirho);
    let mut evidence_chirho = BTreeSet::new();
    for identifier_chirho in identifiers_chirho {
        if target_family_contains_chirho(&identifier_chirho) {
            evidence_chirho.insert(format!("macro-target:{identifier_chirho}"));
        } else if let Some(target_chirho) =
            imports_chirho.target_aliases_chirho.get(&identifier_chirho)
        {
            evidence_chirho.insert(format!(
                "macro-target-alias:{identifier_chirho}->{target_chirho}"
            ));
        }
    }
    evidence_chirho
}

struct H3FunctionReferenceVisitorChirho<'a> {
    file_chirho: &'a str,
    owner_chirho: &'a str,
    owner_is_resident_chirho: bool,
    imports_chirho: &'a H3ImportResolutionChirho,
    known_residents_chirho: BTreeSet<String>,
    block_depth_chirho: usize,
    in_call_callee_chirho: bool,
    inventory_chirho: &'a mut H3TargetInventoryChirho,
}

impl H3FunctionReferenceVisitorChirho<'_> {
    fn insert_target_chirho(&mut self, target_chirho: String, is_call_chirho: bool) {
        let coordinate_chirho = (
            self.file_chirho.to_owned(),
            self.owner_chirho.to_owned(),
            target_chirho,
        );
        *self
            .inventory_chirho
            .coordinates_chirho
            .entry(coordinate_chirho.clone())
            .or_insert(0) += 1;
        let classified_chirho = if is_call_chirho {
            &mut self.inventory_chirho.call_coordinates_chirho
        } else {
            &mut self.inventory_chirho.non_call_coordinates_chirho
        };
        *classified_chirho.entry(coordinate_chirho).or_insert(0) += 1;
    }

    fn unresolved_chirho(&mut self, evidence_chirho: String) {
        self.inventory_chirho.unresolved_chirho.insert((
            self.file_chirho.to_owned(),
            self.owner_chirho.to_owned(),
            evidence_chirho,
        ));
    }

    fn expression_is_resident_chirho(&self, expression_chirho: &Expr) -> bool {
        match expression_chirho {
            Expr::Call(call_chirho) => matches!(
                call_chirho.func.as_ref(),
                Expr::Path(path_chirho)
                    if resolve_target_path_chirho(
                        &path_chirho.path,
                        self.file_chirho,
                        self.imports_chirho,
                        self.owner_is_resident_chirho,
                    )
                    .is_ok_and(|target_chirho| {
                        target_chirho.as_deref() == Some(H3_BIRTH_TARGET_CHIRHO)
                    })
            ),
            Expr::Group(group_chirho) => self.expression_is_resident_chirho(&group_chirho.expr),
            Expr::Paren(paren_chirho) => self.expression_is_resident_chirho(&paren_chirho.expr),
            Expr::Path(path_chirho) => {
                let parts_chirho = path_segments_chirho(&path_chirho.path);
                parts_chirho.len() == 1
                    && ((parts_chirho[0] == "self" && self.owner_is_resident_chirho)
                        || self.known_residents_chirho.contains(&parts_chirho[0]))
            }
            Expr::Reference(reference_chirho) => {
                self.expression_is_resident_chirho(&reference_chirho.expr)
            }
            Expr::Try(try_chirho) => self.expression_is_resident_chirho(&try_chirho.expr),
            _ => false,
        }
    }
}

impl<'ast_chirho> Visit<'ast_chirho> for H3FunctionReferenceVisitorChirho<'_> {
    fn visit_block(&mut self, block_chirho: &'ast_chirho syn::Block) {
        let is_root_chirho = self.block_depth_chirho == 0;
        self.block_depth_chirho += 1;
        for statement_chirho in &block_chirho.stmts {
            if let Stmt::Item(Item::Use(use_chirho)) = statement_chirho {
                if !is_root_chirho {
                    let mut nested_imports_chirho = H3ImportResolutionChirho::default();
                    apply_use_chirho(self.file_chirho, use_chirho, &mut nested_imports_chirho);
                    if !nested_imports_chirho.target_aliases_chirho.is_empty()
                        || !nested_imports_chirho
                            .resident_authority_aliases_chirho
                            .is_empty()
                        || !nested_imports_chirho.birth_permit_aliases_chirho.is_empty()
                        || !nested_imports_chirho.host_module_aliases_chirho.is_empty()
                        || !nested_imports_chirho
                            .regenesis_module_aliases_chirho
                            .is_empty()
                        || nested_imports_chirho.host_glob_chirho
                        || nested_imports_chirho.regenesis_glob_chirho
                        || !nested_imports_chirho.unresolved_chirho.is_empty()
                    {
                        self.unresolved_chirho("nested-use-scope".to_owned());
                    }
                }
                continue;
            }
            self.visit_stmt(statement_chirho);
        }
        self.block_depth_chirho -= 1;
    }

    fn visit_expr_path(&mut self, path_chirho: &'ast_chirho syn::ExprPath) {
        match resolve_target_path_chirho(
            &path_chirho.path,
            self.file_chirho,
            self.imports_chirho,
            self.owner_is_resident_chirho,
        ) {
            Ok(Some(target_chirho)) => {
                self.insert_target_chirho(target_chirho, self.in_call_callee_chirho)
            }
            Err(evidence_chirho) => self.unresolved_chirho(evidence_chirho),
            Ok(None) => {}
        }
        syn::visit::visit_expr_path(self, path_chirho);
    }

    fn visit_expr_call(&mut self, call_chirho: &'ast_chirho syn::ExprCall) {
        let prior_call_callee_chirho = self.in_call_callee_chirho;
        self.in_call_callee_chirho = true;
        self.visit_expr(&call_chirho.func);
        self.in_call_callee_chirho = prior_call_callee_chirho;
        for argument_chirho in &call_chirho.args {
            self.visit_expr(argument_chirho);
        }
    }

    fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
        let method_chirho = ident_name_chirho(&call_chirho.method);
        if method_chirho == H3_APPEND_TARGET_CHIRHO {
            if self.expression_is_resident_chirho(&call_chirho.receiver) {
                self.insert_target_chirho(method_chirho, true);
            } else {
                self.unresolved_chirho(format!("receiver-unresolved:{method_chirho}"));
            }
        } else if target_family_contains_chirho(&method_chirho) {
            self.unresolved_chirho(format!("unexpected-method:{method_chirho}"));
        }
        syn::visit::visit_expr_method_call(self, call_chirho);
    }

    fn visit_local(&mut self, local_chirho: &'ast_chirho syn::Local) {
        let typed_resident_chirho = matches!(
            &local_chirho.pat,
            Pat::Type(type_chirho)
                if type_is_resident_authority_chirho(
                    &type_chirho.ty,
                    self.file_chirho,
                    self.imports_chirho
                )
        );
        let inferred_resident_chirho = local_chirho
            .init
            .as_ref()
            .is_some_and(|init_chirho| self.expression_is_resident_chirho(&init_chirho.expr));
        if let Some(init_chirho) = &local_chirho.init {
            self.visit_expr(&init_chirho.expr);
            if let Some((_else_chirho, diverge_chirho)) = &init_chirho.diverge {
                self.visit_expr(diverge_chirho);
            }
        }
        let mut names_chirho = BTreeSet::new();
        pattern_names_chirho(&local_chirho.pat, &mut names_chirho);
        for name_chirho in &names_chirho {
            if target_family_contains_chirho(name_chirho)
                || self
                    .imports_chirho
                    .target_aliases_chirho
                    .contains_key(name_chirho)
            {
                self.unresolved_chirho(format!("target-shadow:{name_chirho}"));
            }
        }
        if typed_resident_chirho || inferred_resident_chirho {
            self.known_residents_chirho.extend(names_chirho);
        }
    }

    fn visit_macro(&mut self, macro_chirho: &'ast_chirho syn::Macro) {
        for evidence_chirho in macro_target_evidence_chirho(macro_chirho, self.imports_chirho) {
            self.unresolved_chirho(evidence_chirho);
        }
        syn::visit::visit_macro(self, macro_chirho);
    }

    fn visit_item_fn(&mut self, function_chirho: &'ast_chirho syn::ItemFn) {
        let function_name_chirho = ident_name_chirho(&function_chirho.sig.ident);
        if target_family_contains_chirho(&function_name_chirho)
            || self
                .imports_chirho
                .target_aliases_chirho
                .contains_key(&function_name_chirho)
        {
            self.unresolved_chirho(format!("nested-target-shadow:{function_name_chirho}"));
        }
        let nested_owner_chirho = format!("{}::{}", self.owner_chirho, function_chirho.sig.ident);
        collect_function_chirho(
            self.file_chirho,
            &nested_owner_chirho,
            &function_chirho.sig,
            &function_chirho.block,
            false,
            self.imports_chirho,
            self.inventory_chirho,
        );
    }

    fn visit_item_impl(&mut self, implementation_chirho: &'ast_chirho syn::ItemImpl) {
        let nested_type_chirho = type_name_chirho(&implementation_chirho.self_ty);
        let owner_is_resident_chirho = type_is_resident_authority_chirho(
            &implementation_chirho.self_ty,
            self.file_chirho,
            self.imports_chirho,
        );
        for implementation_item_chirho in &implementation_chirho.items {
            match implementation_item_chirho {
                ImplItem::Fn(function_chirho) => {
                    let nested_owner_chirho = format!(
                        "{}::{nested_type_chirho}::{}",
                        self.owner_chirho, function_chirho.sig.ident
                    );
                    collect_function_chirho(
                        self.file_chirho,
                        &nested_owner_chirho,
                        &function_chirho.sig,
                        &function_chirho.block,
                        owner_is_resident_chirho,
                        self.imports_chirho,
                        self.inventory_chirho,
                    );
                }
                ImplItem::Const(constant_chirho) => {
                    let nested_owner_chirho = format!(
                        "{}::{nested_type_chirho}::<const:{}>",
                        self.owner_chirho, constant_chirho.ident
                    );
                    collect_expression_chirho(
                        self.file_chirho,
                        &nested_owner_chirho,
                        &constant_chirho.expr,
                        owner_is_resident_chirho,
                        self.imports_chirho,
                        self.inventory_chirho,
                    );
                }
                _ => {}
            }
        }
    }

    fn visit_item_trait(&mut self, trait_chirho: &'ast_chirho syn::ItemTrait) {
        for trait_item_chirho in &trait_chirho.items {
            match trait_item_chirho {
                syn::TraitItem::Fn(function_chirho) => {
                    let Some(block_chirho) = &function_chirho.default else {
                        continue;
                    };
                    let nested_owner_chirho = format!(
                        "{}::{}::{}",
                        self.owner_chirho, trait_chirho.ident, function_chirho.sig.ident
                    );
                    collect_function_chirho(
                        self.file_chirho,
                        &nested_owner_chirho,
                        &function_chirho.sig,
                        block_chirho,
                        false,
                        self.imports_chirho,
                        self.inventory_chirho,
                    );
                }
                syn::TraitItem::Const(constant_chirho) => {
                    let Some((_equals_chirho, expression_chirho)) = &constant_chirho.default else {
                        continue;
                    };
                    let nested_owner_chirho = format!(
                        "{}::{}::<const:{}>",
                        self.owner_chirho, trait_chirho.ident, constant_chirho.ident
                    );
                    collect_expression_chirho(
                        self.file_chirho,
                        &nested_owner_chirho,
                        expression_chirho,
                        false,
                        self.imports_chirho,
                        self.inventory_chirho,
                    );
                }
                _ => {}
            }
        }
    }

    fn visit_impl_item_fn(&mut self, _function_chirho: &'ast_chirho syn::ImplItemFn) {}

    fn visit_trait_item_fn(&mut self, _function_chirho: &'ast_chirho syn::TraitItemFn) {}
}

fn type_name_chirho(type_chirho: &Type) -> String {
    match type_chirho {
        Type::Path(path_chirho) => path_chirho
            .path
            .segments
            .last()
            .map(|segment_chirho| ident_name_chirho(&segment_chirho.ident))
            .unwrap_or_else(|| "<impl>".to_owned()),
        _ => "<impl>".to_owned(),
    }
}

fn seed_resident_inputs_chirho(
    signature_chirho: &syn::Signature,
    file_chirho: &str,
    imports_chirho: &H3ImportResolutionChirho,
) -> BTreeSet<String> {
    let mut names_chirho = BTreeSet::new();
    for argument_chirho in &signature_chirho.inputs {
        let FnArg::Typed(typed_chirho) = argument_chirho else {
            continue;
        };
        if type_is_resident_authority_chirho(&typed_chirho.ty, file_chirho, imports_chirho) {
            pattern_names_chirho(&typed_chirho.pat, &mut names_chirho);
        }
    }
    names_chirho
}

fn collect_function_chirho(
    file_chirho: &str,
    owner_chirho: &str,
    signature_chirho: &syn::Signature,
    block_chirho: &syn::Block,
    owner_is_resident_chirho: bool,
    module_imports_chirho: &H3ImportResolutionChirho,
    inventory_chirho: &mut H3TargetInventoryChirho,
) {
    let imports_chirho = imports_for_block_chirho(file_chirho, block_chirho, module_imports_chirho);
    for evidence_chirho in &imports_chirho.unresolved_chirho {
        inventory_chirho.unresolved_chirho.insert((
            file_chirho.to_owned(),
            owner_chirho.to_owned(),
            evidence_chirho.clone(),
        ));
    }
    let known_residents_chirho =
        seed_resident_inputs_chirho(signature_chirho, file_chirho, &imports_chirho);
    let mut visitor_chirho = H3FunctionReferenceVisitorChirho {
        file_chirho,
        owner_chirho,
        owner_is_resident_chirho,
        imports_chirho: &imports_chirho,
        known_residents_chirho,
        block_depth_chirho: 0,
        in_call_callee_chirho: false,
        inventory_chirho,
    };
    visitor_chirho.visit_block(block_chirho);
}

fn collect_expression_chirho(
    file_chirho: &str,
    owner_chirho: &str,
    expression_chirho: &Expr,
    owner_is_resident_chirho: bool,
    imports_chirho: &H3ImportResolutionChirho,
    inventory_chirho: &mut H3TargetInventoryChirho,
) {
    let mut visitor_chirho = H3FunctionReferenceVisitorChirho {
        file_chirho,
        owner_chirho,
        owner_is_resident_chirho,
        imports_chirho,
        known_residents_chirho: BTreeSet::new(),
        block_depth_chirho: 0,
        in_call_callee_chirho: false,
        inventory_chirho,
    };
    visitor_chirho.visit_expr(expression_chirho);
}

fn record_macro_targets_chirho(
    file_chirho: &str,
    owner_chirho: &str,
    macro_chirho: &syn::Macro,
    imports_chirho: &H3ImportResolutionChirho,
    inventory_chirho: &mut H3TargetInventoryChirho,
) {
    for evidence_chirho in macro_target_evidence_chirho(macro_chirho, imports_chirho) {
        inventory_chirho.unresolved_chirho.insert((
            file_chirho.to_owned(),
            owner_chirho.to_owned(),
            evidence_chirho,
        ));
    }
}

pub(super) fn h3_target_inventory_for_source_chirho(
    file_chirho: &str,
    syntax_chirho: &syn::File,
) -> H3TargetInventoryChirho {
    let module_imports_chirho = module_imports_for_syntax_chirho(file_chirho, syntax_chirho);
    let mut inventory_chirho = H3TargetInventoryChirho::default();
    for evidence_chirho in &module_imports_chirho.unresolved_chirho {
        inventory_chirho.unresolved_chirho.insert((
            file_chirho.to_owned(),
            "<module>".to_owned(),
            evidence_chirho.clone(),
        ));
    }
    for item_chirho in &syntax_chirho.items {
        match item_chirho {
            Item::Fn(function_chirho) => collect_function_chirho(
                file_chirho,
                &ident_name_chirho(&function_chirho.sig.ident),
                &function_chirho.sig,
                &function_chirho.block,
                false,
                &module_imports_chirho,
                &mut inventory_chirho,
            ),
            Item::Impl(implementation_chirho) => {
                let owner_type_chirho = type_name_chirho(&implementation_chirho.self_ty);
                let owner_is_resident_chirho = type_is_resident_authority_chirho(
                    &implementation_chirho.self_ty,
                    file_chirho,
                    &module_imports_chirho,
                );
                for implementation_item_chirho in &implementation_chirho.items {
                    match implementation_item_chirho {
                        ImplItem::Fn(function_chirho) => collect_function_chirho(
                            file_chirho,
                            &format!("{owner_type_chirho}::{}", function_chirho.sig.ident),
                            &function_chirho.sig,
                            &function_chirho.block,
                            owner_is_resident_chirho,
                            &module_imports_chirho,
                            &mut inventory_chirho,
                        ),
                        ImplItem::Const(constant_chirho) => collect_expression_chirho(
                            file_chirho,
                            &format!("{owner_type_chirho}::<const:{}>", constant_chirho.ident),
                            &constant_chirho.expr,
                            owner_is_resident_chirho,
                            &module_imports_chirho,
                            &mut inventory_chirho,
                        ),
                        ImplItem::Macro(macro_chirho) => record_macro_targets_chirho(
                            file_chirho,
                            &format!("{owner_type_chirho}::<macro>"),
                            &macro_chirho.mac,
                            &module_imports_chirho,
                            &mut inventory_chirho,
                        ),
                        _ => {}
                    }
                }
            }
            Item::Trait(trait_chirho) => {
                for trait_item_chirho in &trait_chirho.items {
                    match trait_item_chirho {
                        syn::TraitItem::Fn(function_chirho) => {
                            let Some(block_chirho) = &function_chirho.default else {
                                continue;
                            };
                            collect_function_chirho(
                                file_chirho,
                                &format!("{}::{}", trait_chirho.ident, function_chirho.sig.ident),
                                &function_chirho.sig,
                                block_chirho,
                                false,
                                &module_imports_chirho,
                                &mut inventory_chirho,
                            );
                        }
                        syn::TraitItem::Const(constant_chirho) => {
                            let Some((_equals_chirho, expression_chirho)) =
                                &constant_chirho.default
                            else {
                                continue;
                            };
                            collect_expression_chirho(
                                file_chirho,
                                &format!(
                                    "{}::<const:{}>",
                                    trait_chirho.ident, constant_chirho.ident
                                ),
                                expression_chirho,
                                false,
                                &module_imports_chirho,
                                &mut inventory_chirho,
                            );
                        }
                        syn::TraitItem::Macro(macro_chirho) => record_macro_targets_chirho(
                            file_chirho,
                            &format!("{}::<macro>", trait_chirho.ident),
                            &macro_chirho.mac,
                            &module_imports_chirho,
                            &mut inventory_chirho,
                        ),
                        _ => {}
                    }
                }
            }
            Item::Const(constant_chirho) => collect_expression_chirho(
                file_chirho,
                &format!("<const:{}>", constant_chirho.ident),
                &constant_chirho.expr,
                false,
                &module_imports_chirho,
                &mut inventory_chirho,
            ),
            Item::Static(static_chirho) => collect_expression_chirho(
                file_chirho,
                &format!("<static:{}>", static_chirho.ident),
                &static_chirho.expr,
                false,
                &module_imports_chirho,
                &mut inventory_chirho,
            ),
            Item::Macro(macro_chirho) => record_macro_targets_chirho(
                file_chirho,
                "<module-macro>",
                &macro_chirho.mac,
                &module_imports_chirho,
                &mut inventory_chirho,
            ),
            Item::Mod(module_chirho) => {
                let Some((_brace_chirho, nested_items_chirho)) = &module_chirho.content else {
                    continue;
                };
                let nested_syntax_chirho = syn::File {
                    shebang: None,
                    attrs: Vec::new(),
                    items: nested_items_chirho.clone(),
                };
                let nested_inventory_chirho =
                    h3_target_inventory_for_source_chirho(file_chirho, &nested_syntax_chirho);
                let module_name_chirho = ident_name_chirho(&module_chirho.ident);
                for ((nested_file_chirho, owner_chirho, target_chirho), count_chirho) in
                    nested_inventory_chirho.coordinates_chirho
                {
                    *inventory_chirho
                        .coordinates_chirho
                        .entry((
                            nested_file_chirho,
                            format!("{module_name_chirho}::{owner_chirho}"),
                            target_chirho,
                        ))
                        .or_insert(0) += count_chirho;
                }
                for ((nested_file_chirho, owner_chirho, target_chirho), count_chirho) in
                    nested_inventory_chirho.call_coordinates_chirho
                {
                    *inventory_chirho
                        .call_coordinates_chirho
                        .entry((
                            nested_file_chirho,
                            format!("{module_name_chirho}::{owner_chirho}"),
                            target_chirho,
                        ))
                        .or_insert(0) += count_chirho;
                }
                for ((nested_file_chirho, owner_chirho, target_chirho), count_chirho) in
                    nested_inventory_chirho.non_call_coordinates_chirho
                {
                    *inventory_chirho
                        .non_call_coordinates_chirho
                        .entry((
                            nested_file_chirho,
                            format!("{module_name_chirho}::{owner_chirho}"),
                            target_chirho,
                        ))
                        .or_insert(0) += count_chirho;
                }
                for (nested_file_chirho, owner_chirho, evidence_chirho) in
                    nested_inventory_chirho.unresolved_chirho
                {
                    inventory_chirho.unresolved_chirho.insert((
                        nested_file_chirho,
                        format!("{module_name_chirho}::{owner_chirho}"),
                        evidence_chirho,
                    ));
                }
            }
            _ => {}
        }
    }
    inventory_chirho
}

pub(super) fn h3_target_inventory_chirho() -> H3TargetInventoryChirho {
    let mut inventory_chirho = H3TargetInventoryChirho::default();
    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let raw_source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let source_chirho = production_text_chirho(&raw_source_chirho);
        let syntax_chirho = syn::parse_file(&source_chirho).unwrap_or_else(|error_chirho| {
            panic!("H3 exact-target inventory must parse {relative_chirho}: {error_chirho}")
        });
        let source_inventory_chirho =
            h3_target_inventory_for_source_chirho(&relative_chirho, &syntax_chirho);
        for (coordinate_chirho, count_chirho) in source_inventory_chirho.coordinates_chirho {
            *inventory_chirho
                .coordinates_chirho
                .entry(coordinate_chirho)
                .or_insert(0) += count_chirho;
        }
        for (coordinate_chirho, count_chirho) in source_inventory_chirho.call_coordinates_chirho {
            *inventory_chirho
                .call_coordinates_chirho
                .entry(coordinate_chirho)
                .or_insert(0) += count_chirho;
        }
        for (coordinate_chirho, count_chirho) in source_inventory_chirho.non_call_coordinates_chirho
        {
            *inventory_chirho
                .non_call_coordinates_chirho
                .entry(coordinate_chirho)
                .or_insert(0) += count_chirho;
        }
        inventory_chirho
            .unresolved_chirho
            .extend(source_inventory_chirho.unresolved_chirho);
    }
    inventory_chirho
}

#[test]
fn h3_exact_target_resolver_catches_alias_local_use_and_function_values_chirho() {
    let syntax_chirho = syn::parse_file(
        r#"
        use cairn_ledger_host_chirho::ResidentLedgerAuthorityChirho as ResidentChirho;
        fn activate_alias_chirho() {
            use cairn_ledger_host_chirho::activate_reviewed_h3_chirho as start_chirho;
            let callback_chirho = start_chirho;
            callback_chirho();
        }
        fn birth_value_chirho() {
            let callback_chirho = ResidentChirho::create_bound_preactivation_chirho;
            callback_chirho();
        }
        fn append_value_chirho() {
            let callback_chirho = ResidentChirho::append_preactivation_chirho;
            callback_chirho();
        }
        "#,
    )
    .unwrap();
    let inventory_chirho =
        h3_target_inventory_for_source_chirho("fixture_chirho.rs", &syntax_chirho);
    assert!(inventory_chirho.unresolved_chirho.is_empty());
    assert_eq!(
        inventory_chirho
            .coordinates_chirho
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            (
                "fixture_chirho.rs".to_owned(),
                "activate_alias_chirho".to_owned(),
                H3_ACTIVATION_TARGET_CHIRHO.to_owned(),
            ),
            (
                "fixture_chirho.rs".to_owned(),
                "append_value_chirho".to_owned(),
                H3_APPEND_TARGET_CHIRHO.to_owned(),
            ),
            (
                "fixture_chirho.rs".to_owned(),
                "birth_value_chirho".to_owned(),
                H3_BIRTH_TARGET_CHIRHO.to_owned(),
            ),
        ])
    );
    assert!(inventory_chirho.call_coordinates_chirho.is_empty());
    assert_eq!(
        inventory_chirho
            .non_call_coordinates_chirho
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        inventory_chirho
            .coordinates_chirho
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        "function-value references must never masquerade as direct callers"
    );
}

#[test]
fn h3_exact_target_resolver_calls_grouped_regenesis_module_alias_chirho() {
    let syntax_chirho = syn::parse_file(
        r#"
        use cairn_ledger_regenesis_chirho::{self as regenesis_chirho};
        fn author_chirho() {
            (regenesis_chirho::author_ledger_regenesis_activation_chirho)(request_chirho);
        }
        "#,
    )
    .unwrap();
    let inventory_chirho =
        h3_target_inventory_for_source_chirho("fixture_chirho.rs", &syntax_chirho);
    assert!(inventory_chirho.unresolved_chirho.is_empty());
    assert_eq!(
        inventory_chirho.call_coordinates_chirho,
        BTreeMap::from([(
            (
                "fixture_chirho.rs".to_owned(),
                "author_chirho".to_owned(),
                H3_AUTHOR_TARGET_CHIRHO.to_owned(),
            ),
            1,
        )])
    );
    assert!(inventory_chirho.non_call_coordinates_chirho.is_empty());
}

#[test]
fn h3_exact_target_resolver_exercises_unresolved_fail_closed_chirho() {
    let syntax_chirho = syn::parse_file(
        r#"
        fn unknown_chirho() {
            let callback_chirho = mystery_chirho::activate_reviewed_h3_chirho;
            callback_chirho();
            unknown_resident_chirho.append_preactivation_chirho();
        }
        "#,
    )
    .unwrap();
    let inventory_chirho =
        h3_target_inventory_for_source_chirho("fixture_chirho.rs", &syntax_chirho);
    assert!(inventory_chirho.coordinates_chirho.is_empty());
    assert_eq!(
        inventory_chirho.unresolved_chirho,
        BTreeSet::from([
            (
                "fixture_chirho.rs".to_owned(),
                "unknown_chirho".to_owned(),
                "path:mystery_chirho::activate_reviewed_h3_chirho".to_owned(),
            ),
            (
                "fixture_chirho.rs".to_owned(),
                "unknown_chirho".to_owned(),
                "receiver-unresolved:append_preactivation_chirho".to_owned(),
            ),
        ])
    );
}

#[test]
fn h3_exact_target_resolver_scans_nested_functions_and_constant_values_chirho() {
    let syntax_chirho = syn::parse_file(
        r#"
        const ACTIVATE_CHIRHO: fn() =
            cairn_ledger_host_chirho::activate_reviewed_h3_chirho;

        fn outer_chirho() {
            fn nested_chirho() {
                let callback_chirho =
                    cairn_ledger_host_chirho::activate_reviewed_h3_chirho;
                callback_chirho();
            }
            nested_chirho();
        }
        "#,
    )
    .unwrap();
    let inventory_chirho =
        h3_target_inventory_for_source_chirho("fixture_chirho.rs", &syntax_chirho);
    assert!(inventory_chirho.unresolved_chirho.is_empty());
    assert_eq!(
        inventory_chirho
            .coordinates_chirho
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            (
                "fixture_chirho.rs".to_owned(),
                "<const:ACTIVATE_CHIRHO>".to_owned(),
                H3_ACTIVATION_TARGET_CHIRHO.to_owned(),
            ),
            (
                "fixture_chirho.rs".to_owned(),
                "outer_chirho::nested_chirho".to_owned(),
                H3_ACTIVATION_TARGET_CHIRHO.to_owned(),
            ),
        ])
    );
}

#[test]
fn h3_exact_target_resolver_covers_inline_raw_alias_macro_and_scope_evasions_chirho() {
    let inline_raw_chirho = syn::parse_file(
        r#"
        mod hidden_chirho {
            use cairn_ledger_host_chirho::ResidentLedgerAuthorityChirho;

            fn call_chirho(resident_chirho: &ResidentLedgerAuthorityChirho) {
                cairn_ledger_host_chirho::r#activate_reviewed_h3_chirho();
                resident_chirho.r#append_preactivation_chirho();
            }
        }
        "#,
    )
    .unwrap();
    let inline_inventory_chirho =
        h3_target_inventory_for_source_chirho("fixture_chirho.rs", &inline_raw_chirho);
    assert!(inline_inventory_chirho.unresolved_chirho.is_empty());
    assert_eq!(
        inline_inventory_chirho
            .coordinates_chirho
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            (
                "fixture_chirho.rs".to_owned(),
                "hidden_chirho::call_chirho".to_owned(),
                H3_ACTIVATION_TARGET_CHIRHO.to_owned(),
            ),
            (
                "fixture_chirho.rs".to_owned(),
                "hidden_chirho::call_chirho".to_owned(),
                H3_APPEND_TARGET_CHIRHO.to_owned(),
            ),
        ])
    );

    for source_chirho in [
        r#"
        fn wrong_module_chirho() {
            unrelated_chirho::activation_chirho::activate_reviewed_h3_chirho();
        }
        "#,
        r#"
        pub use cairn_ledger_host_chirho::activate_reviewed_h3_chirho as hidden_chirho;
        fn reexport_call_chirho() {
            hidden_chirho();
        }
        "#,
        r#"
        use cairn_ledger_host_chirho::activate_reviewed_h3_chirho as start_chirho;
        fn macro_call_chirho() {
            invoke_chirho!(start_chirho);
        }
        "#,
        r#"
        fn nested_scope_chirho() {
            {
                use cairn_ledger_host_chirho::activate_reviewed_h3_chirho as hidden_chirho;
                hidden_chirho();
            }
        }
        "#,
    ] {
        let syntax_chirho = syn::parse_file(source_chirho).unwrap();
        let inventory_chirho =
            h3_target_inventory_for_source_chirho("fixture_chirho.rs", &syntax_chirho);
        assert!(
            !inventory_chirho.unresolved_chirho.is_empty(),
            "ambiguous H3 target spellings must fail closed"
        );
    }
}
