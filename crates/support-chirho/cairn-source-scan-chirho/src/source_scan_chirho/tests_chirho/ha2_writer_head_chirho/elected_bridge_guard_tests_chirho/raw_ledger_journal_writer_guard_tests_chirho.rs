// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Exact production inventory for raw ledger-journal constructors and mutations.
//!
//! This is deliberately a conservative `syn` resolver, not a claim to provide rustc HIR/type
//! resolution. It resolves reviewed import and local-typing shapes and fails closed whenever a
//! journal-aware production source contains a mutation-family reference whose receiver cannot be
//! classified. Macro expansion, arbitrary trait dispatch, and cross-crate inferred return types
//! remain outside `syn`'s proof boundary; a new raw writer must therefore spell or import the
//! journal type in its owning source, or this guard must be upgraded before that shape is accepted.

use super::*;
#[path = "raw_ledger_journal_writer_roles_chirho.rs"]
mod raw_ledger_journal_writer_roles_chirho;
use raw_ledger_journal_writer_roles_chirho::{
    role_for_writer_chirho, source_owns_journal_impl_chirho,
};
use std::collections::{BTreeMap, BTreeSet};
use syn::visit::Visit;
use syn::{
    Expr, FnArg, GenericArgument, ImplItem, Item, Pat, PathArguments, ReturnType, Type, UseTree,
};

type WriterCoordinateChirho = (String, String, String, String);
type ExpectedWriterCoordinateChirho = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    usize,
);
type UnresolvedWriterReferenceChirho = (String, String, String);

const CONSTRUCTOR_FAMILY_CHIRHO: [&str; 8] = [
    "create_chirho",
    "create_prepared_chirho",
    "open_chirho",
    "open_read_only_chirho",
    "open_read_only_exact_head_checkpoint_chirho",
    "open_read_only_full_chirho",
    "open_read_only_with_expected_genesis_chirho",
    "open_with_expected_genesis_chirho",
];

// These methods cross the crate boundary and return the raw journal type. `syn` cannot resolve
// their inferred return type from a call site, so this reviewed target family is the explicit
// bridge. Unknown mutation-family receivers still fail closed below.
const JOURNAL_RETURNING_METHOD_FAMILY_CHIRHO: [&str; 2] =
    ["create_journal_chirho", "open_journal_chirho"];

// Filled from the production AST below. The expected set is intentionally tuples, not a count:
// every file/owner/operation must carry a reviewed role.
const EXPECTED_WRITER_COORDINATES_CHIRHO: [ExpectedWriterCoordinateChirho; 59] = [
    (
        "crates/cairn-serve-runtime-chirho/src/serve_chirho/ledger_host_runtime_chirho.rs",
        "LedgerHostProjectionReadPortChirho::read_substrate_balances_chirho",
        "open_read_only_chirho",
        "served-runtime-observer",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-effect-commit-ledger-chirho/src/adapter_chirho.rs",
        "LedgerEffectCommitAdapterChirho::append_compensation_hold_chirho",
        "append_effect_compensation_chirho",
        "runtime-effect-adapter",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-effect-commit-ledger-chirho/src/adapter_chirho.rs",
        "LedgerEffectCommitAdapterChirho::append_hold_chirho",
        "append_effect_intent_chirho",
        "runtime-effect-adapter",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-effect-commit-ledger-chirho/src/adapter_chirho.rs",
        "LedgerEffectCommitAdapterChirho::append_terminal_chirho",
        "append_effect_terminal_chirho",
        "runtime-effect-adapter",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-composition-chirho/src/composition_chirho.rs",
        "JournalConservationSourceChirho::load_verified_head_consistent_snapshot_chirho",
        "open_read_only_full_chirho",
        "runtime-raw-composition",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-composition-chirho/src/composition_chirho.rs",
        "LedgerWriteCompositionChirho::create_journal_chirho",
        "create_chirho",
        "runtime-raw-composition",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-composition-chirho/src/composition_chirho.rs",
        "LedgerWriteCompositionChirho::open_journal_chirho",
        "open_chirho",
        "runtime-raw-composition",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/activation_chirho.rs",
        "activate_reviewed_h3_chirho",
        "open_read_only_chirho",
        "reviewed-h3-activation-verifier",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/birth_chirho.rs",
        "ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho",
        "create_prepared_chirho",
        "sealed-preactivation-resident-birth",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/birth_chirho.rs",
        "ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho",
        "open_read_only_chirho",
        "sealed-preactivation-resident-birth",
        2,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/held_coordinator_chirho/adoption_chirho.rs",
        "materialize_gd7_held_adoption_candidate_with_projection_chirho",
        "open_read_only_full_chirho",
        "gd7-held-adoption-materializer",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/held_coordinator_chirho/adoption_commit_chirho.rs",
        "require_candidate_measurements_chirho",
        "open_read_only_full_chirho",
        "gd7-held-adoption-restart-verifier",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho/recovery_adoption_chirho.rs",
        "full_open_chirho",
        "open_read_only_full_chirho",
        "mirror-recovery-candidate-verifier",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/resident_mutation_chirho/authority_open_view_chirho.rs",
        "ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho",
        "open_read_only_with_expected_genesis_chirho",
        "sealed-resident-authority",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho.rs",
        "ResidentLedgerAuthorityChirho::append_with_current_fence_chirho",
        "advance_epoch_chirho",
        "sealed-resident-authority",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho.rs",
        "ResidentLedgerAuthorityChirho::append_with_current_fence_chirho",
        "append_chirho",
        "sealed-resident-authority",
        2,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho.rs",
        "ResidentLedgerAuthorityChirho::append_with_current_fence_chirho",
        "append_effect_compensation_chirho",
        "sealed-resident-authority",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho.rs",
        "ResidentLedgerAuthorityChirho::append_with_current_fence_chirho",
        "append_effect_intent_chirho",
        "sealed-resident-authority",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho.rs",
        "ResidentLedgerAuthorityChirho::append_with_current_fence_chirho",
        "append_effect_terminal_chirho",
        "sealed-resident-authority",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_chirho.rs",
        "LedgerJournalChirho::advance_epoch_chirho",
        "define:advance_epoch_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_chirho/append_execution_chirho.rs",
        "LedgerJournalChirho::append_chirho",
        "append_request_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_chirho/append_execution_chirho.rs",
        "LedgerJournalChirho::append_chirho",
        "define:append_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_chirho/append_execution_chirho.rs",
        "LedgerJournalChirho::append_request_chirho",
        "define:append_request_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_chirho.rs",
        "LedgerJournalChirho::create_chirho",
        "create_prepared_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_chirho.rs",
        "LedgerJournalChirho::create_chirho",
        "define:create_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_chirho.rs",
        "LedgerJournalChirho::create_prepared_chirho",
        "define:create_prepared_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_chirho.rs",
        "LedgerJournalChirho::open_chirho",
        "define:open_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_chirho.rs",
        "LedgerJournalChirho::open_read_only_chirho",
        "define:open_read_only_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_chirho.rs",
        "LedgerJournalChirho::open_read_only_chirho",
        "open_read_only_full_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_chirho.rs",
        "LedgerJournalChirho::open_read_only_exact_head_checkpoint_chirho",
        "define:open_read_only_exact_head_checkpoint_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_chirho.rs",
        "LedgerJournalChirho::open_read_only_full_chirho",
        "define:open_read_only_full_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_chirho.rs",
        "LedgerJournalChirho::rotate_chirho",
        "define:rotate_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_chirho/verified_prefix_state_chirho.rs",
        "open_read_only_verified_prefix_state_chirho",
        "open_read_only_full_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_chirho/verified_prefix_state_chirho.rs",
        "open_read_only_verified_tail_cut_chirho",
        "open_read_only_full_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_effect_chirho.rs",
        "LedgerJournalChirho::append_effect_compensation_chirho",
        "append_new_effect_hold_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_effect_chirho.rs",
        "LedgerJournalChirho::append_effect_compensation_chirho",
        "define:append_effect_compensation_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_effect_chirho.rs",
        "LedgerJournalChirho::append_effect_intent_chirho",
        "append_new_effect_hold_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_effect_chirho.rs",
        "LedgerJournalChirho::append_effect_intent_chirho",
        "define:append_effect_intent_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_effect_chirho.rs",
        "LedgerJournalChirho::append_effect_terminal_chirho",
        "append_request_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_effect_chirho.rs",
        "LedgerJournalChirho::append_effect_terminal_chirho",
        "define:append_effect_terminal_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_effect_chirho.rs",
        "LedgerJournalChirho::append_new_effect_hold_chirho",
        "append_request_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_effect_chirho.rs",
        "LedgerJournalChirho::append_new_effect_hold_chirho",
        "define:append_new_effect_hold_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_fastopen_chirho.rs",
        "LedgerJournalChirho::open_read_only_with_expected_genesis_chirho",
        "define:open_read_only_with_expected_genesis_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_fastopen_chirho.rs",
        "LedgerJournalChirho::open_read_only_with_expected_genesis_chirho",
        "open_read_only_full_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_fastopen_chirho.rs",
        "LedgerJournalChirho::open_with_expected_genesis_chirho",
        "define:open_with_expected_genesis_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_fastopen_chirho.rs",
        "LedgerJournalChirho::write_head_checkpoint_chirho",
        "define:write_head_checkpoint_chirho",
        "journal-substrate",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/registry_chirho.rs",
        "LedgerActorRegistryChirho::passivate_chirho",
        "write_head_checkpoint_chirho",
        "runtime-actor-registry",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/registry_chirho.rs",
        "LedgerActorRegistryChirho::process_all_chirho",
        "append_chirho",
        "runtime-actor-registry",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-log-chirho/src/registry_chirho.rs",
        "LedgerActorRegistryChirho::submit_chirho",
        "open_chirho",
        "runtime-actor-registry",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-read-model-chirho/src/evidence_group_chirho/localphaseb_evidence_chirho.rs",
        "verified_journal_walk_chirho",
        "open_read_only_full_chirho",
        "read-model-observer",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-read-model-chirho/src/feed_group_chirho/feeder_chirho.rs",
        "equivalence_canary_chirho",
        "open_read_only_chirho",
        "read-model-observer",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-read-model-chirho/src/feed_group_chirho/feeder_chirho.rs",
        "feed_projection_once_chirho",
        "open_read_only_chirho",
        "read-model-observer",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-read-model-chirho/src/feed_group_chirho/heartbeat_chirho.rs",
        "heartbeat_promise_violation_check_chirho",
        "open_read_only_chirho",
        "read-model-observer",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-read-model-chirho/src/feed_group_chirho/heartbeat_chirho.rs",
        "mint_source_heartbeat_chirho",
        "open_read_only_chirho",
        "read-model-observer",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-read-model-chirho/src/feed_group_chirho/merge_feeder_chirho.rs",
        "extract_verified_source_prefix_chirho",
        "open_read_only_chirho",
        "read-model-observer",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-read-model-chirho/src/serve_group_chirho/merge_serving_chirho.rs",
        "serve_merge_follower_read_chirho",
        "open_read_only_chirho",
        "read-model-observer",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-read-model-chirho/src/serve_group_chirho/serving_chirho.rs",
        "serve_follower_read_with_posture_chirho",
        "open_read_only_chirho",
        "read-model-observer",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-regenesis-chirho/src/publication_verify_chirho.rs",
        "verify_staged_resident_chirho",
        "open_read_only_full_chirho",
        "offline-regenesis",
        1,
    ),
    (
        "crates/ledger-chirho/cairn-ledger-regenesis-chirho/src/money_stage_chirho.rs",
        "provision_money_chirho",
        "open_read_only_chirho",
        "offline-regenesis",
        1,
    ),
];

#[derive(Clone, Debug, Default)]
struct ImportResolutionChirho {
    journal_type_aliases_chirho: BTreeSet<String>,
    journal_module_aliases_chirho: BTreeSet<String>,
    glob_imports_journal_chirho: bool,
    unresolved_chirho: BTreeSet<String>,
}

#[derive(Clone, Debug, Default)]
struct SourceMetadataChirho {
    imports_chirho: ImportResolutionChirho,
    journal_aware_chirho: bool,
    journal_struct_fields_chirho: BTreeSet<String>,
    journal_returning_functions_chirho: BTreeSet<String>,
    journal_returning_methods_chirho: BTreeSet<String>,
}

#[derive(Clone, Debug, Default)]
struct WriterInventoryChirho {
    coordinates_chirho: BTreeMap<WriterCoordinateChirho, usize>,
    unresolved_chirho: BTreeSet<UnresolvedWriterReferenceChirho>,
}

fn is_constructor_name_chirho(name_chirho: &str) -> bool {
    CONSTRUCTOR_FAMILY_CHIRHO.contains(&name_chirho)
}

fn is_mutation_family_name_chirho(name_chirho: &str) -> bool {
    name_chirho.starts_with("append")
        || name_chirho.contains("epoch")
        || name_chirho.contains("checkpoint")
        || name_chirho.contains("rotate")
}

fn path_segments_chirho(path_chirho: &syn::Path) -> Vec<String> {
    path_chirho
        .segments
        .iter()
        .map(|segment_chirho| segment_chirho.ident.to_string())
        .collect()
}

fn collect_use_leaves_chirho(
    tree_chirho: &UseTree,
    prefix_chirho: &mut Vec<String>,
    leaves_chirho: &mut Vec<(Vec<String>, String, bool)>,
) {
    match tree_chirho {
        UseTree::Path(path_chirho) => {
            prefix_chirho.push(path_chirho.ident.to_string());
            collect_use_leaves_chirho(&path_chirho.tree, prefix_chirho, leaves_chirho);
            prefix_chirho.pop();
        }
        UseTree::Name(name_chirho) => {
            let mut target_chirho = prefix_chirho.clone();
            target_chirho.push(name_chirho.ident.to_string());
            leaves_chirho.push((target_chirho, name_chirho.ident.to_string(), false));
        }
        UseTree::Rename(rename_chirho) => {
            let mut target_chirho = prefix_chirho.clone();
            if rename_chirho.ident != "self" {
                target_chirho.push(rename_chirho.ident.to_string());
            }
            leaves_chirho.push((target_chirho, rename_chirho.rename.to_string(), false));
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

fn path_is_journal_module_chirho(path_chirho: &[String]) -> bool {
    path_chirho
        .last()
        .is_some_and(|part_chirho| part_chirho == "journal_chirho")
        && (path_chirho
            .iter()
            .any(|part_chirho| part_chirho == "cairn_ledger_log_chirho")
            || path_chirho.iter().any(|part_chirho| part_chirho == "crate"))
}

fn path_is_journal_type_target_chirho(path_chirho: &[String]) -> bool {
    path_chirho
        .last()
        .is_some_and(|part_chirho| part_chirho == "LedgerJournalChirho")
        && path_chirho
            .windows(2)
            .any(|parts_chirho| parts_chirho == ["journal_chirho", "LedgerJournalChirho"])
}

fn imports_for_syntax_chirho(syntax_chirho: &syn::File) -> ImportResolutionChirho {
    struct ImportVisitorChirho {
        resolution_chirho: ImportResolutionChirho,
    }

    impl<'ast_chirho> Visit<'ast_chirho> for ImportVisitorChirho {
        fn visit_item_use(&mut self, use_chirho: &'ast_chirho syn::ItemUse) {
            let mut leaves_chirho = Vec::new();
            collect_use_leaves_chirho(&use_chirho.tree, &mut Vec::new(), &mut leaves_chirho);
            for (target_chirho, alias_chirho, glob_chirho) in leaves_chirho {
                let journal_target_chirho = path_is_journal_type_target_chirho(&target_chirho);
                let journal_module_chirho = path_is_journal_module_chirho(&target_chirho);
                if glob_chirho && journal_module_chirho {
                    self.resolution_chirho.glob_imports_journal_chirho = true;
                } else if journal_target_chirho {
                    self.resolution_chirho
                        .journal_type_aliases_chirho
                        .insert(alias_chirho.clone());
                } else if journal_module_chirho {
                    self.resolution_chirho
                        .journal_module_aliases_chirho
                        .insert(alias_chirho.clone());
                }
                if !matches!(use_chirho.vis, syn::Visibility::Inherited)
                    && (journal_target_chirho || journal_module_chirho)
                {
                    self.resolution_chirho
                        .unresolved_chirho
                        .insert(format!("public-journal-reexport:{alias_chirho}"));
                }
            }
            syn::visit::visit_item_use(self, use_chirho);
        }
    }

    let mut visitor_chirho = ImportVisitorChirho {
        resolution_chirho: ImportResolutionChirho::default(),
    };
    visitor_chirho.visit_file(syntax_chirho);
    visitor_chirho.resolution_chirho
}

fn path_resolves_journal_type_chirho(
    path_chirho: &syn::Path,
    imports_chirho: &ImportResolutionChirho,
    owner_is_journal_impl_chirho: bool,
) -> bool {
    let parts_chirho = path_segments_chirho(path_chirho);
    let Some(last_chirho) = parts_chirho.last() else {
        return false;
    };
    if last_chirho == "Self" && owner_is_journal_impl_chirho {
        return true;
    }
    if imports_chirho
        .journal_type_aliases_chirho
        .contains(last_chirho)
    {
        return true;
    }
    if last_chirho != "LedgerJournalChirho" {
        return false;
    }
    if parts_chirho.len() == 1 {
        return owner_is_journal_impl_chirho
            || imports_chirho.glob_imports_journal_chirho
            || imports_chirho
                .journal_type_aliases_chirho
                .contains("LedgerJournalChirho");
    }
    parts_chirho[..parts_chirho.len() - 1]
        .iter()
        .any(|part_chirho| {
            part_chirho == "journal_chirho"
                || imports_chirho
                    .journal_module_aliases_chirho
                    .contains(part_chirho)
        })
}

fn type_contains_journal_chirho(
    type_chirho: &Type,
    imports_chirho: &ImportResolutionChirho,
    owner_is_journal_impl_chirho: bool,
) -> bool {
    match type_chirho {
        Type::Array(array_chirho) => type_contains_journal_chirho(
            &array_chirho.elem,
            imports_chirho,
            owner_is_journal_impl_chirho,
        ),
        Type::BareFn(function_chirho) => {
            function_chirho.inputs.iter().any(|input_chirho| {
                type_contains_journal_chirho(
                    &input_chirho.ty,
                    imports_chirho,
                    owner_is_journal_impl_chirho,
                )
            }) || return_type_contains_journal_chirho(
                &function_chirho.output,
                imports_chirho,
                owner_is_journal_impl_chirho,
            )
        }
        Type::Group(group_chirho) => type_contains_journal_chirho(
            &group_chirho.elem,
            imports_chirho,
            owner_is_journal_impl_chirho,
        ),
        Type::Paren(paren_chirho) => type_contains_journal_chirho(
            &paren_chirho.elem,
            imports_chirho,
            owner_is_journal_impl_chirho,
        ),
        Type::Path(path_chirho) => {
            path_resolves_journal_type_chirho(
                &path_chirho.path,
                imports_chirho,
                owner_is_journal_impl_chirho,
            ) || path_chirho.path.segments.iter().any(|segment_chirho| {
                let PathArguments::AngleBracketed(arguments_chirho) = &segment_chirho.arguments
                else {
                    return false;
                };
                arguments_chirho.args.iter().any(|argument_chirho| {
                    matches!(
                        argument_chirho,
                        GenericArgument::Type(nested_chirho)
                            if type_contains_journal_chirho(
                                nested_chirho,
                                imports_chirho,
                                owner_is_journal_impl_chirho
                            )
                    )
                })
            })
        }
        Type::Ptr(pointer_chirho) => type_contains_journal_chirho(
            &pointer_chirho.elem,
            imports_chirho,
            owner_is_journal_impl_chirho,
        ),
        Type::Reference(reference_chirho) => type_contains_journal_chirho(
            &reference_chirho.elem,
            imports_chirho,
            owner_is_journal_impl_chirho,
        ),
        Type::Slice(slice_chirho) => type_contains_journal_chirho(
            &slice_chirho.elem,
            imports_chirho,
            owner_is_journal_impl_chirho,
        ),
        Type::Tuple(tuple_chirho) => tuple_chirho.elems.iter().any(|element_chirho| {
            type_contains_journal_chirho(
                element_chirho,
                imports_chirho,
                owner_is_journal_impl_chirho,
            )
        }),
        _ => false,
    }
}

fn return_type_contains_journal_chirho(
    output_chirho: &ReturnType,
    imports_chirho: &ImportResolutionChirho,
    owner_is_journal_impl_chirho: bool,
) -> bool {
    matches!(
        output_chirho,
        ReturnType::Type(_, type_chirho)
            if type_contains_journal_chirho(
                type_chirho,
                imports_chirho,
                owner_is_journal_impl_chirho
            )
    )
}

fn type_name_chirho(type_chirho: &Type) -> Option<String> {
    let Type::Path(path_chirho) = type_chirho else {
        return None;
    };
    path_chirho
        .path
        .segments
        .last()
        .map(|segment_chirho| segment_chirho.ident.to_string())
}

fn impl_is_journal_chirho(
    implementation_chirho: &syn::ItemImpl,
    metadata_chirho: &SourceMetadataChirho,
    file_chirho: &str,
) -> bool {
    type_contains_journal_chirho(
        &implementation_chirho.self_ty,
        &metadata_chirho.imports_chirho,
        source_owns_journal_impl_chirho(file_chirho),
    )
}

fn metadata_for_source_chirho(
    file_chirho: &str,
    syntax_chirho: &syn::File,
) -> SourceMetadataChirho {
    let imports_chirho = imports_for_syntax_chirho(syntax_chirho);
    let mut metadata_chirho = SourceMetadataChirho {
        journal_aware_chirho: source_owns_journal_impl_chirho(file_chirho)
            || !imports_chirho.journal_type_aliases_chirho.is_empty()
            || imports_chirho.glob_imports_journal_chirho,
        imports_chirho,
        ..SourceMetadataChirho::default()
    };

    for item_chirho in &syntax_chirho.items {
        match item_chirho {
            Item::Struct(struct_chirho) => {
                for field_chirho in &struct_chirho.fields {
                    if type_contains_journal_chirho(
                        &field_chirho.ty,
                        &metadata_chirho.imports_chirho,
                        false,
                    ) {
                        metadata_chirho.journal_aware_chirho = true;
                        if let Some(name_chirho) = &field_chirho.ident {
                            metadata_chirho
                                .journal_struct_fields_chirho
                                .insert(name_chirho.to_string());
                        }
                    }
                }
            }
            Item::Fn(function_chirho) => {
                if return_type_contains_journal_chirho(
                    &function_chirho.sig.output,
                    &metadata_chirho.imports_chirho,
                    false,
                ) {
                    metadata_chirho
                        .journal_returning_functions_chirho
                        .insert(function_chirho.sig.ident.to_string());
                }
            }
            Item::Impl(implementation_chirho) => {
                let owner_is_journal_chirho =
                    impl_is_journal_chirho(implementation_chirho, &metadata_chirho, file_chirho);
                for implementation_item_chirho in &implementation_chirho.items {
                    let ImplItem::Fn(function_chirho) = implementation_item_chirho else {
                        continue;
                    };
                    if return_type_contains_journal_chirho(
                        &function_chirho.sig.output,
                        &metadata_chirho.imports_chirho,
                        owner_is_journal_chirho,
                    ) {
                        metadata_chirho
                            .journal_returning_methods_chirho
                            .insert(function_chirho.sig.ident.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    metadata_chirho
}

fn has_mutable_receiver_chirho(signature_chirho: &syn::Signature) -> bool {
    signature_chirho.inputs.iter().any(|argument_chirho| {
        matches!(
            argument_chirho,
            FnArg::Receiver(receiver_chirho)
                if receiver_chirho.reference.is_some()
                    && receiver_chirho.mutability.is_some()
        )
    })
}

fn method_writes_journal_storage_chirho(signature_chirho: &syn::Signature) -> bool {
    let name_chirho = signature_chirho.ident.to_string();
    (has_mutable_receiver_chirho(signature_chirho) && is_mutation_family_name_chirho(&name_chirho))
        || name_chirho == "write_head_checkpoint_chirho"
}

fn mutation_methods_for_sources_chirho(sources_chirho: &[(String, syn::File)]) -> BTreeSet<String> {
    let mut methods_chirho = BTreeSet::new();
    for (file_chirho, syntax_chirho) in sources_chirho {
        let metadata_chirho = metadata_for_source_chirho(file_chirho, syntax_chirho);
        for item_chirho in &syntax_chirho.items {
            let Item::Impl(implementation_chirho) = item_chirho else {
                continue;
            };
            if !impl_is_journal_chirho(implementation_chirho, &metadata_chirho, file_chirho) {
                continue;
            }
            for implementation_item_chirho in &implementation_chirho.items {
                let ImplItem::Fn(function_chirho) = implementation_item_chirho else {
                    continue;
                };
                let name_chirho = function_chirho.sig.ident.to_string();
                if method_writes_journal_storage_chirho(&function_chirho.sig) {
                    methods_chirho.insert(name_chirho);
                }
            }
        }
    }
    methods_chirho
}

fn constructor_from_path_chirho(
    path_chirho: &syn::Path,
    imports_chirho: &ImportResolutionChirho,
    owner_is_journal_impl_chirho: bool,
) -> Result<Option<String>, String> {
    let parts_chirho = path_segments_chirho(path_chirho);
    let Some(operation_chirho) = parts_chirho.last() else {
        return Ok(None);
    };
    if !is_constructor_name_chirho(operation_chirho) {
        return Ok(None);
    }
    if parts_chirho.len() < 2 {
        return Err(format!("bare-constructor:{operation_chirho}"));
    }
    let mut type_path_chirho = path_chirho.clone();
    type_path_chirho.segments.pop();
    if path_resolves_journal_type_chirho(
        &type_path_chirho,
        imports_chirho,
        owner_is_journal_impl_chirho,
    ) {
        Ok(Some(operation_chirho.clone()))
    } else if parts_chirho
        .iter()
        .any(|part_chirho| part_chirho == "LedgerJournalChirho")
        || parts_chirho.iter().any(|part_chirho| {
            imports_chirho
                .journal_type_aliases_chirho
                .contains(part_chirho)
        })
    {
        Err(format!("constructor-path:{}", parts_chirho.join("::")))
    } else {
        Ok(None)
    }
}

fn pattern_names_chirho(pattern_chirho: &Pat, names_chirho: &mut BTreeSet<String>) {
    match pattern_chirho {
        Pat::Ident(ident_chirho) => {
            names_chirho.insert(ident_chirho.ident.to_string());
            if let Some((_at_chirho, nested_chirho)) = &ident_chirho.subpat {
                pattern_names_chirho(nested_chirho, names_chirho);
            }
        }
        Pat::Reference(reference_chirho) => {
            pattern_names_chirho(&reference_chirho.pat, names_chirho)
        }
        Pat::Slice(slice_chirho) => {
            for element_chirho in &slice_chirho.elems {
                pattern_names_chirho(element_chirho, names_chirho);
            }
        }
        Pat::Struct(struct_chirho) => {
            for field_chirho in &struct_chirho.fields {
                pattern_names_chirho(&field_chirho.pat, names_chirho);
            }
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

struct FunctionBodyVisitorChirho<'a> {
    file_chirho: &'a str,
    owner_chirho: &'a str,
    owner_is_journal_impl_chirho: bool,
    metadata_chirho: &'a SourceMetadataChirho,
    mutation_methods_chirho: &'a BTreeSet<String>,
    known_journal_locals_chirho: BTreeSet<String>,
    inventory_chirho: &'a mut WriterInventoryChirho,
}

impl FunctionBodyVisitorChirho<'_> {
    fn insert_coordinate_chirho(&mut self, operation_chirho: String) {
        let Some(role_chirho) = role_for_writer_chirho(self.file_chirho) else {
            self.inventory_chirho.unresolved_chirho.insert((
                self.file_chirho.to_owned(),
                self.owner_chirho.to_owned(),
                format!("unclassified-role:{operation_chirho}"),
            ));
            return;
        };
        *self
            .inventory_chirho
            .coordinates_chirho
            .entry((
                self.file_chirho.to_owned(),
                self.owner_chirho.to_owned(),
                operation_chirho,
                role_chirho.to_owned(),
            ))
            .or_insert(0) += 1;
    }

    fn unresolved_chirho(&mut self, evidence_chirho: String) {
        self.inventory_chirho.unresolved_chirho.insert((
            self.file_chirho.to_owned(),
            self.owner_chirho.to_owned(),
            evidence_chirho,
        ));
    }

    fn expression_is_journal_chirho(&self, expression_chirho: &Expr) -> bool {
        match expression_chirho {
            Expr::Call(call_chirho) => match call_chirho.func.as_ref() {
                Expr::Path(path_chirho) => {
                    constructor_from_path_chirho(
                        &path_chirho.path,
                        &self.metadata_chirho.imports_chirho,
                        self.owner_is_journal_impl_chirho,
                    )
                    .is_ok_and(|operation_chirho| operation_chirho.is_some())
                        || path_chirho
                            .path
                            .segments
                            .last()
                            .is_some_and(|segment_chirho| {
                                self.metadata_chirho
                                    .journal_returning_functions_chirho
                                    .contains(&segment_chirho.ident.to_string())
                            })
                }
                _ => self.expression_is_journal_chirho(&call_chirho.func),
            },
            Expr::Field(field_chirho) => match &field_chirho.member {
                syn::Member::Named(name_chirho) => self
                    .metadata_chirho
                    .journal_struct_fields_chirho
                    .contains(&name_chirho.to_string()),
                syn::Member::Unnamed(_) => false,
            },
            Expr::Group(group_chirho) => self.expression_is_journal_chirho(&group_chirho.expr),
            Expr::MethodCall(call_chirho) => {
                let method_chirho = call_chirho.method.to_string();
                self.metadata_chirho
                    .journal_returning_methods_chirho
                    .contains(&method_chirho)
                    || JOURNAL_RETURNING_METHOD_FAMILY_CHIRHO.contains(&method_chirho.as_str())
                    || (matches!(
                        method_chirho.as_str(),
                        "as_mut"
                            | "as_ref"
                            | "as_deref"
                            | "as_deref_mut"
                            | "expect"
                            | "map_err"
                            | "unwrap"
                            | "with_finality_views_chirho"
                    ) && self.expression_is_journal_chirho(&call_chirho.receiver))
            }
            Expr::Paren(paren_chirho) => self.expression_is_journal_chirho(&paren_chirho.expr),
            Expr::Path(path_chirho) => {
                let parts_chirho = path_segments_chirho(&path_chirho.path);
                parts_chirho.len() == 1
                    && ((parts_chirho[0] == "self" && self.owner_is_journal_impl_chirho)
                        || self.known_journal_locals_chirho.contains(&parts_chirho[0]))
            }
            Expr::Reference(reference_chirho) => {
                self.expression_is_journal_chirho(&reference_chirho.expr)
            }
            Expr::Try(try_chirho) => self.expression_is_journal_chirho(&try_chirho.expr),
            _ => false,
        }
    }

    fn local_is_typed_journal_chirho(&self, local_chirho: &syn::Local) -> bool {
        matches!(
            &local_chirho.pat,
            Pat::Type(type_chirho)
                if type_contains_journal_chirho(
                    &type_chirho.ty,
                    &self.metadata_chirho.imports_chirho,
                    self.owner_is_journal_impl_chirho
                )
        )
    }
}

impl<'ast_chirho> Visit<'ast_chirho> for FunctionBodyVisitorChirho<'_> {
    fn visit_expr_path(&mut self, path_chirho: &'ast_chirho syn::ExprPath) {
        match constructor_from_path_chirho(
            &path_chirho.path,
            &self.metadata_chirho.imports_chirho,
            self.owner_is_journal_impl_chirho,
        ) {
            Ok(Some(operation_chirho)) => self.insert_coordinate_chirho(operation_chirho),
            Err(evidence_chirho) if self.metadata_chirho.journal_aware_chirho => {
                self.unresolved_chirho(evidence_chirho)
            }
            Ok(None) | Err(_) => {}
        }
        syn::visit::visit_expr_path(self, path_chirho);
    }

    fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
        let method_chirho = call_chirho.method.to_string();
        if self.mutation_methods_chirho.contains(&method_chirho) {
            if self.expression_is_journal_chirho(&call_chirho.receiver) {
                self.insert_coordinate_chirho(method_chirho);
            } else if self.metadata_chirho.journal_aware_chirho {
                self.unresolved_chirho(format!("typed-receiver-unresolved:{method_chirho}"));
            }
        }
        syn::visit::visit_expr_method_call(self, call_chirho);
    }

    fn visit_local(&mut self, local_chirho: &'ast_chirho syn::Local) {
        let inferred_journal_chirho = self.local_is_typed_journal_chirho(local_chirho)
            || local_chirho
                .init
                .as_ref()
                .is_some_and(|init_chirho| self.expression_is_journal_chirho(&init_chirho.expr));
        if let Some(init_chirho) = &local_chirho.init {
            self.visit_expr(&init_chirho.expr);
            if let Some((_else_chirho, diverge_chirho)) = &init_chirho.diverge {
                self.visit_expr(diverge_chirho);
            }
        }
        if inferred_journal_chirho {
            let mut names_chirho = BTreeSet::new();
            pattern_names_chirho(&local_chirho.pat, &mut names_chirho);
            self.known_journal_locals_chirho.extend(names_chirho);
        }
    }

    fn visit_macro(&mut self, macro_chirho: &'ast_chirho syn::Macro) {
        if self.metadata_chirho.journal_aware_chirho {
            let token_text_chirho = macro_chirho.tokens.to_string();
            if token_text_chirho.contains("LedgerJournalChirho")
                || CONSTRUCTOR_FAMILY_CHIRHO
                    .iter()
                    .any(|name_chirho| token_text_chirho.contains(name_chirho))
                || self
                    .mutation_methods_chirho
                    .iter()
                    .any(|name_chirho| token_text_chirho.contains(name_chirho))
            {
                self.unresolved_chirho("macro-journal-family-reference".to_owned());
            }
        }
        syn::visit::visit_macro(self, macro_chirho);
    }

    fn visit_item_fn(&mut self, _function_chirho: &'ast_chirho syn::ItemFn) {}

    fn visit_impl_item_fn(&mut self, _function_chirho: &'ast_chirho syn::ImplItemFn) {}
}

fn seed_typed_inputs_chirho(
    signature_chirho: &syn::Signature,
    metadata_chirho: &SourceMetadataChirho,
    owner_is_journal_impl_chirho: bool,
) -> BTreeSet<String> {
    let mut names_chirho = BTreeSet::new();
    for argument_chirho in &signature_chirho.inputs {
        let FnArg::Typed(typed_chirho) = argument_chirho else {
            continue;
        };
        if type_contains_journal_chirho(
            &typed_chirho.ty,
            &metadata_chirho.imports_chirho,
            owner_is_journal_impl_chirho,
        ) {
            pattern_names_chirho(&typed_chirho.pat, &mut names_chirho);
        }
    }
    names_chirho
}

struct WriterScanContextChirho<'scan_chirho> {
    metadata_chirho: &'scan_chirho SourceMetadataChirho,
    mutation_methods_chirho: &'scan_chirho BTreeSet<String>,
}

fn collect_function_chirho(
    file_chirho: &str,
    owner_chirho: &str,
    signature_chirho: &syn::Signature,
    block_chirho: &syn::Block,
    owner_is_journal_impl_chirho: bool,
    context_chirho: &WriterScanContextChirho<'_>,
    inventory_chirho: &mut WriterInventoryChirho,
) {
    let mut visitor_chirho = FunctionBodyVisitorChirho {
        file_chirho,
        owner_chirho,
        owner_is_journal_impl_chirho,
        metadata_chirho: context_chirho.metadata_chirho,
        mutation_methods_chirho: context_chirho.mutation_methods_chirho,
        known_journal_locals_chirho: seed_typed_inputs_chirho(
            signature_chirho,
            context_chirho.metadata_chirho,
            owner_is_journal_impl_chirho,
        ),
        inventory_chirho,
    };
    visitor_chirho.visit_block(block_chirho);
}

fn inventory_source_chirho(
    file_chirho: &str,
    syntax_chirho: &syn::File,
    mutation_methods_chirho: &BTreeSet<String>,
) -> WriterInventoryChirho {
    let metadata_chirho = metadata_for_source_chirho(file_chirho, syntax_chirho);
    let context_chirho = WriterScanContextChirho {
        metadata_chirho: &metadata_chirho,
        mutation_methods_chirho,
    };
    let mut inventory_chirho = WriterInventoryChirho::default();
    for evidence_chirho in &metadata_chirho.imports_chirho.unresolved_chirho {
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
                &function_chirho.sig.ident.to_string(),
                &function_chirho.sig,
                &function_chirho.block,
                false,
                &context_chirho,
                &mut inventory_chirho,
            ),
            Item::Impl(implementation_chirho) => {
                let owner_type_chirho = type_name_chirho(&implementation_chirho.self_ty)
                    .unwrap_or_else(|| "<impl>".to_owned());
                let owner_is_journal_chirho =
                    impl_is_journal_chirho(implementation_chirho, &metadata_chirho, file_chirho);
                for implementation_item_chirho in &implementation_chirho.items {
                    let ImplItem::Fn(function_chirho) = implementation_item_chirho else {
                        continue;
                    };
                    let method_chirho = function_chirho.sig.ident.to_string();
                    if owner_is_journal_chirho
                        && (is_constructor_name_chirho(&method_chirho)
                            || mutation_methods_chirho.contains(&method_chirho))
                    {
                        let operation_chirho = format!("define:{method_chirho}");
                        if let Some(role_chirho) = role_for_writer_chirho(file_chirho) {
                            *inventory_chirho
                                .coordinates_chirho
                                .entry((
                                    file_chirho.to_owned(),
                                    format!("{owner_type_chirho}::{method_chirho}"),
                                    operation_chirho,
                                    role_chirho.to_owned(),
                                ))
                                .or_insert(0) += 1;
                        } else {
                            inventory_chirho.unresolved_chirho.insert((
                                file_chirho.to_owned(),
                                format!("{owner_type_chirho}::{method_chirho}"),
                                format!("unclassified-role:{operation_chirho}"),
                            ));
                        }
                    }
                    collect_function_chirho(
                        file_chirho,
                        &format!("{owner_type_chirho}::{}", function_chirho.sig.ident),
                        &function_chirho.sig,
                        &function_chirho.block,
                        owner_is_journal_chirho,
                        &context_chirho,
                        &mut inventory_chirho,
                    );
                }
            }
            _ => {}
        }
    }
    inventory_chirho
}

fn production_syntaxes_chirho() -> Vec<(String, syn::File)> {
    workspace_production_rs_files_chirho()
        .into_iter()
        .filter_map(|path_chirho| {
            let relative_chirho = workspace_relative_chirho(&path_chirho);
            let raw_chirho = std::fs::read_to_string(&path_chirho).unwrap();
            let source_chirho = production_text_chirho(&raw_chirho);
            if !source_owns_journal_impl_chirho(&relative_chirho)
                && !source_chirho.contains("LedgerJournalChirho")
            {
                return None;
            }
            let syntax_chirho = syn::parse_file(&source_chirho).unwrap_or_else(|error_chirho| {
                panic!("raw journal writer guard must parse {relative_chirho}: {error_chirho}")
            });
            Some((relative_chirho, syntax_chirho))
        })
        .collect()
}

fn production_writer_inventory_chirho() -> WriterInventoryChirho {
    let sources_chirho = production_syntaxes_chirho();
    let mutation_methods_chirho = mutation_methods_for_sources_chirho(&sources_chirho);
    let mut inventory_chirho = WriterInventoryChirho::default();
    for (file_chirho, syntax_chirho) in &sources_chirho {
        let source_inventory_chirho =
            inventory_source_chirho(file_chirho, syntax_chirho, &mutation_methods_chirho);
        for (coordinate_chirho, occurrences_chirho) in source_inventory_chirho.coordinates_chirho {
            *inventory_chirho
                .coordinates_chirho
                .entry(coordinate_chirho)
                .or_insert(0) += occurrences_chirho;
        }
        inventory_chirho
            .unresolved_chirho
            .extend(source_inventory_chirho.unresolved_chirho);
    }
    inventory_chirho
}

fn expected_writer_inventory_chirho() -> BTreeMap<WriterCoordinateChirho, usize> {
    EXPECTED_WRITER_COORDINATES_CHIRHO
        .iter()
        .map(
            |(file_chirho, owner_chirho, operation_chirho, role_chirho, occurrences_chirho)| {
                (
                    (
                        (*file_chirho).to_owned(),
                        (*owner_chirho).to_owned(),
                        (*operation_chirho).to_owned(),
                        (*role_chirho).to_owned(),
                    ),
                    *occurrences_chirho,
                )
            },
        )
        .collect()
}

#[test]
fn production_raw_ledger_journal_writer_surface_is_exact_chirho() {
    let inventory_chirho = production_writer_inventory_chirho();
    assert!(
        inventory_chirho.unresolved_chirho.is_empty(),
        "LedgerJournalChirho writer references must resolve and carry an explicit role; unknown is evidence, never absence: {:?}",
        inventory_chirho.unresolved_chirho
    );
    assert_eq!(
        inventory_chirho.coordinates_chirho,
        expected_writer_inventory_chirho(),
        "production raw LedgerJournalChirho writer surface changed; classify every file/owner/operation/occurrence role"
    );
}

fn synthetic_inventory_chirho(source_chirho: &str) -> WriterInventoryChirho {
    let syntax_chirho = syn::parse_file(source_chirho).unwrap();
    inventory_source_chirho(
        "crates/ledger-chirho/cairn-ledger-sim-chirho/src/synthetic_chirho.rs",
        &syntax_chirho,
        &BTreeSet::from(["append_chirho".to_owned()]),
    )
}

#[test]
fn raw_writer_scanner_resolves_direct_and_aliased_constructors_chirho() {
    let inventory_chirho = synthetic_inventory_chirho(
        r#"
        use cairn_ledger_log_chirho::journal_chirho::{
            LedgerJournalChirho,
            LedgerJournalChirho as JournalAliasChirho,
        };
        fn direct_constructor_chirho() {
            let _journal_chirho = LedgerJournalChirho::create_chirho();
        }
        fn aliased_constructor_chirho() {
            use cairn_ledger_log_chirho::journal_chirho::LedgerJournalChirho as LocalJournalChirho;
            let _first_chirho = JournalAliasChirho::open_chirho();
            let _second_chirho = LocalJournalChirho::create_prepared_chirho();
        }
        "#,
    );
    assert!(inventory_chirho.unresolved_chirho.is_empty());
    assert_eq!(
        inventory_chirho
            .coordinates_chirho
            .keys()
            .map(|coordinate_chirho| { (coordinate_chirho.1.clone(), coordinate_chirho.2.clone()) })
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            (
                "aliased_constructor_chirho".to_owned(),
                "create_prepared_chirho".to_owned(),
            ),
            (
                "aliased_constructor_chirho".to_owned(),
                "open_chirho".to_owned(),
            ),
            (
                "direct_constructor_chirho".to_owned(),
                "create_chirho".to_owned(),
            ),
        ])
    );
}

#[test]
fn raw_writer_scanner_resolves_typed_receiver_mutation_chirho() {
    let inventory_chirho = synthetic_inventory_chirho(
        r#"
        use cairn_ledger_log_chirho::journal_chirho::LedgerJournalChirho;
        fn mutate_chirho(journal_chirho: &mut LedgerJournalChirho<'_>) {
            journal_chirho.append_chirho();
        }
        "#,
    );
    assert!(inventory_chirho.unresolved_chirho.is_empty());
    assert_eq!(
        inventory_chirho
            .coordinates_chirho
            .keys()
            .map(|coordinate_chirho| coordinate_chirho.2.clone())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["append_chirho".to_owned()])
    );
}

#[test]
fn raw_writer_scanner_resolves_self_and_composition_returned_journal_chirho() {
    let inventory_chirho = synthetic_inventory_chirho(
        r#"
        use cairn_ledger_log_chirho::journal_chirho::LedgerJournalChirho;
        struct HarnessChirho;
        impl LedgerJournalChirho<'_> {
            fn delegate_chirho(&mut self) {
                self.append_chirho();
            }
        }
        fn composition_chirho(harness_chirho: HarnessChirho) {
            let mut journal_chirho = harness_chirho
                .create_journal_chirho()
                .map_err(|_error_chirho| ())?;
            journal_chirho.append_chirho();
            Ok::<(), ()>(())
        }
        "#,
    );
    assert!(inventory_chirho.unresolved_chirho.is_empty());
    assert_eq!(
        inventory_chirho
            .coordinates_chirho
            .keys()
            .map(|coordinate_chirho| (coordinate_chirho.1.clone(), coordinate_chirho.2.clone()))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            (
                "LedgerJournalChirho::delegate_chirho".to_owned(),
                "append_chirho".to_owned(),
            ),
            ("composition_chirho".to_owned(), "append_chirho".to_owned(),),
        ])
    );
}

#[test]
fn raw_writer_scanner_fails_closed_on_unresolved_family_receiver_chirho() {
    let inventory_chirho = synthetic_inventory_chirho(
        r#"
        use cairn_ledger_log_chirho::journal_chirho::LedgerJournalChirho;
        fn unresolved_chirho(mystery_chirho: MysteryChirho) {
            mystery_chirho.append_chirho();
        }
        "#,
    );
    assert!(inventory_chirho.coordinates_chirho.is_empty());
    assert_eq!(
        inventory_chirho.unresolved_chirho,
        BTreeSet::from([(
            "crates/ledger-chirho/cairn-ledger-sim-chirho/src/synthetic_chirho.rs".to_owned(),
            "unresolved_chirho".to_owned(),
            "typed-receiver-unresolved:append_chirho".to_owned(),
        )])
    );
}
