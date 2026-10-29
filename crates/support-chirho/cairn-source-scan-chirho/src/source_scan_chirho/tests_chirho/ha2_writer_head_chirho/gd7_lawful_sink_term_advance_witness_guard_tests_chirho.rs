// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pins the private GD7 witness and the reviewed raw sink-cell mover population.
//!
//! The raw mover is shared by birth, ordinary-election, and GD7 code paths. The exact AST census
//! below makes every added or relocated caller explicit; private single-construction proof types
//! remain the primary controls for the authority-bearing mid-life paths.

use super::super::*;
use std::collections::{BTreeMap, BTreeSet};
use syn::visit::Visit;

const WITNESS_MODULE_PATH_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/sink_term_revoke_chirho.rs";
const WITNESS_TYPE_NEEDLE_CHIRHO: &str = "struct VerifiedLawfulSinkTermAdvanceChirho {";
const WITNESS_FIELD_NEEDLES_CHIRHO: &[&str] =
    &["group_digest_chirho: String", "accepted_term_chirho: u64"];
const WITNESS_CONSTRUCTION_NEEDLE_CHIRHO: &str = "VerifiedLawfulSinkTermAdvanceChirho {";
/// The two coordinates the advance binds. Both must resolve in production, or the module has
/// stopped requiring one of them.
const BOUND_COORDINATE_NEEDLES_CHIRHO: &[&str] = &[
    "published_raft_term_chirho()",
    "load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho(",
    "advance_accepted_winner_term_chirho(",
];
const RAW_SINK_TERM_ADVANCE_CHIRHO: &str = "advance_accepted_winner_term_chirho";
const ORDINARY_TERM_PROOF_CHIRHO: &str = "VerifiedOrdinaryElectionSinkTermAcceptanceChirho";
const ORDINARY_TERM_PROOF_PATH_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-log-chirho/src/journal_chirho/recovery_mirror_chirho.rs";
const ORDINARY_TERM_PLACEMENT_BINDING_CHIRHO: &str =
    "LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho";
const MIRROR_RUNTIME_PORTS_CHIRHO: &str = "LedgerMirrorRuntimePortsChirho";
const MIRROR_COMPOSITION_PATH_CHIRHO: &str =
    "crates/stores-chirho/cairn-ledger-mirror-http-chirho/src/composition_chirho.rs";

#[derive(Default)]
struct RawSinkTermAdvanceCallVisitorChirho {
    calls_chirho: usize,
}

impl<'ast_chirho> Visit<'ast_chirho> for RawSinkTermAdvanceCallVisitorChirho {
    fn visit_expr_call(&mut self, call_chirho: &'ast_chirho syn::ExprCall) {
        if let syn::Expr::Path(path_chirho) = call_chirho.func.as_ref() {
            if path_chirho
                .path
                .segments
                .last()
                .is_some_and(|segment_chirho| segment_chirho.ident == RAW_SINK_TERM_ADVANCE_CHIRHO)
            {
                self.calls_chirho += 1;
            }
        }
        syn::visit::visit_expr_call(self, call_chirho);
    }
}

#[derive(Default)]
struct ProofConstructionVisitorChirho {
    self_structs_chirho: usize,
}

#[derive(Default)]
struct OrdinaryTermCompositionCallVisitorChirho {
    placement_binding_constructors_chirho: usize,
    runtime_port_constructors_chirho: usize,
}

fn call_is_type_constructor_chirho(call_chirho: &syn::ExprCall, type_name_chirho: &str) -> bool {
    let syn::Expr::Path(path_chirho) = call_chirho.func.as_ref() else {
        return false;
    };
    let mut segments_chirho = path_chirho.path.segments.iter().rev();
    segments_chirho
        .next()
        .is_some_and(|segment_chirho| segment_chirho.ident == "new_chirho")
        && segments_chirho
            .next()
            .is_some_and(|segment_chirho| segment_chirho.ident == type_name_chirho)
}

impl<'ast_chirho> Visit<'ast_chirho> for OrdinaryTermCompositionCallVisitorChirho {
    fn visit_expr_call(&mut self, call_chirho: &'ast_chirho syn::ExprCall) {
        if call_is_type_constructor_chirho(call_chirho, ORDINARY_TERM_PLACEMENT_BINDING_CHIRHO) {
            self.placement_binding_constructors_chirho += 1;
        }
        if call_is_type_constructor_chirho(call_chirho, MIRROR_RUNTIME_PORTS_CHIRHO) {
            self.runtime_port_constructors_chirho += 1;
        }
        syn::visit::visit_expr_call(self, call_chirho);
    }
}

impl<'ast_chirho> Visit<'ast_chirho> for ProofConstructionVisitorChirho {
    fn visit_expr_struct(&mut self, expression_chirho: &'ast_chirho syn::ExprStruct) {
        if expression_chirho
            .path
            .segments
            .last()
            .is_some_and(|segment_chirho| segment_chirho.ident == "Self")
        {
            self.self_structs_chirho += 1;
        }
        syn::visit::visit_expr_struct(self, expression_chirho);
    }
}

fn witness_source_chirho() -> String {
    let module_path_chirho = workspace_root_chirho().join(WITNESS_MODULE_PATH_CHIRHO);
    assert!(
        module_path_chirho.is_file(),
        "lawful advance witness module moved or disappeared"
    );
    let raw_chirho = std::fs::read_to_string(&module_path_chirho)
        .unwrap_or_else(|_| panic!("read {WITNESS_MODULE_PATH_CHIRHO}"));
    production_text_chirho(&raw_chirho).into_owned()
}

fn witness_struct_body_chirho(source_chirho: &str) -> &str {
    let declaration_offset_chirho = source_chirho
        .find(WITNESS_TYPE_NEEDLE_CHIRHO)
        .expect("lawful advance witness declaration needle");
    let body_start_chirho = declaration_offset_chirho + WITNESS_TYPE_NEEDLE_CHIRHO.len();
    let body_end_chirho = source_chirho[body_start_chirho..]
        .find('}')
        .map(|offset_chirho| body_start_chirho + offset_chirho)
        .expect("lawful advance witness body terminator");
    &source_chirho[body_start_chirho..body_end_chirho]
}

#[test]
fn gd7_lawful_advance_witness_module_type_and_fields_are_live_once_chirho() {
    let production_paths_chirho = workspace_production_rs_files_chirho();
    let module_path_chirho = workspace_root_chirho().join(WITNESS_MODULE_PATH_CHIRHO);
    assert_eq!(
        production_paths_chirho
            .iter()
            .filter(|path_chirho| *path_chirho == &module_path_chirho)
            .count(),
        1,
        "lawful advance witness module must resolve exactly once in production"
    );

    let source_chirho = witness_source_chirho();
    assert_eq!(
        source_chirho.matches(WITNESS_TYPE_NEEDLE_CHIRHO).count(),
        1,
        "lawful advance witness type declaration must resolve exactly once"
    );
    let struct_body_chirho = witness_struct_body_chirho(&source_chirho);
    for field_needle_chirho in WITNESS_FIELD_NEEDLES_CHIRHO {
        assert_eq!(
            struct_body_chirho.matches(field_needle_chirho).count(),
            1,
            "lawful advance witness field {field_needle_chirho} must resolve exactly once"
        );
        assert!(
            struct_body_chirho
                .lines()
                .filter(|line_chirho| line_chirho.contains(field_needle_chirho))
                .all(|line_chirho| {
                    field_line_is_private_chirho(line_chirho, field_needle_chirho)
                }),
            "lawful advance witness field {field_needle_chirho} must remain private; widening visibility dissolves the capability tier"
        );
    }
}

#[test]
fn gd7_lawful_advance_witness_has_one_production_constructor_and_live_needles_chirho() {
    let source_chirho = witness_source_chirho();
    let construction_count_chirho = source_chirho
        .lines()
        .filter(|line_chirho| {
            line_chirho.contains(WITNESS_CONSTRUCTION_NEEDLE_CHIRHO)
                && !line_chirho.contains("struct ")
                && !line_chirho.contains("impl ")
                && !line_chirho.contains("->")
                // A `compile_fail` doc example names the literal precisely to prove a caller
                // CANNOT build it. Counting documentation as a construction site would make the
                // proof of confinement read as a breach of it.
                && !line_chirho.trim_start().starts_with("///")
        })
        .count();
    assert_eq!(
        construction_count_chirho, 1,
        "lawful advance witness must have exactly one production construction site; a second constructor needs an authority review"
    );
    for field_needle_chirho in WITNESS_FIELD_NEEDLES_CHIRHO {
        assert!(
            source_chirho.contains(field_needle_chirho),
            "lawful advance witness field needle {field_needle_chirho} became unfindable"
        );
    }
}

#[test]
fn gd7_lawful_advance_still_binds_both_coordinates_and_the_cut_chirho() {
    // Needle liveness with a purpose: each of these is a coordinate the advance is required to
    // bind. If one stops resolving, the module has stopped consulting it — which is exactly the
    // silent weakening the two-coordinate contract exists to prevent.
    let source_chirho = witness_source_chirho();
    for coordinate_needle_chirho in BOUND_COORDINATE_NEEDLES_CHIRHO {
        assert!(
            source_chirho.contains(coordinate_needle_chirho),
            "lawful advance no longer references {coordinate_needle_chirho}; the two-coordinate contract has been weakened or renamed"
        );
    }
}

#[test]
fn every_raw_sink_term_advance_caller_is_an_exact_reviewed_mover_chirho() {
    let mut callers_chirho = BTreeMap::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let raw_chirho = std::fs::read_to_string(&path_chirho)
            .unwrap_or_else(|_| panic!("read {relative_chirho}"));
        let production_chirho = production_text_chirho(&raw_chirho);
        let syntax_chirho = syn::parse_file(&production_chirho)
            .unwrap_or_else(|_| panic!("parse {relative_chirho}"));
        let mut population_chirho = RawSinkTermAdvanceCallVisitorChirho::default();
        population_chirho.visit_file(&syntax_chirho);
        if population_chirho.calls_chirho > 0 {
            callers_chirho.insert(relative_chirho, population_chirho.calls_chirho);
        }
    }
    assert_eq!(
        callers_chirho,
        BTreeMap::from([
            (
                "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/ordinary_term_acceptance_chirho.rs".to_owned(),
                1,
            ),
            (
                "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/sink_term_lifecycle_chirho.rs".to_owned(),
                1,
            ),
            (
                "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/sink_term_revoke_chirho.rs".to_owned(),
                2,
            ),
        ]),
        "the raw durable sink-term mover gained, lost, or relocated a production caller; every new caller is money-fence authority and requires its own proof boundary"
    );
}

#[test]
fn ordinary_term_authority_join_has_one_reviewed_production_minter_chirho() {
    let mut placement_binding_constructors_chirho = BTreeMap::new();
    let mut runtime_port_constructors_chirho = BTreeMap::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        let raw_chirho = std::fs::read_to_string(&path_chirho)
            .unwrap_or_else(|_| panic!("read {relative_chirho}"));
        let production_chirho = production_text_chirho(&raw_chirho);
        let syntax_chirho = syn::parse_file(&production_chirho)
            .unwrap_or_else(|_| panic!("parse {relative_chirho}"));
        let mut population_chirho = OrdinaryTermCompositionCallVisitorChirho::default();
        population_chirho.visit_file(&syntax_chirho);
        if population_chirho.placement_binding_constructors_chirho > 0 {
            placement_binding_constructors_chirho.insert(
                relative_chirho.clone(),
                population_chirho.placement_binding_constructors_chirho,
            );
        }
        if population_chirho.runtime_port_constructors_chirho > 0 {
            runtime_port_constructors_chirho.insert(
                relative_chirho,
                population_chirho.runtime_port_constructors_chirho,
            );
        }
    }
    let reviewed_composition_chirho =
        BTreeMap::from([(MIRROR_COMPOSITION_PATH_CHIRHO.to_owned(), 1)]);
    assert_eq!(
        placement_binding_constructors_chirho, reviewed_composition_chirho,
        "the local placement expectation has exactly one production minter, inside the composition that derives it from verified placement; another construction site is money-fence authority and requires review"
    );
    assert_eq!(
        runtime_port_constructors_chirho,
        BTreeMap::from([(MIRROR_COMPOSITION_PATH_CHIRHO.to_owned(), 1)]),
        "the inseparable append/recovery/ordinary-term runtime port set has exactly one production minter; another construction site could pair evidence with a different authority population"
    );
}

#[test]
fn ordinary_term_advance_proof_fields_and_constructor_stay_private_and_exact_chirho() {
    let source_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(ORDINARY_TERM_PROOF_PATH_CHIRHO))
            .expect("read ordinary-term proof owner");
    let production_chirho = production_text_chirho(&source_chirho);
    let syntax_chirho =
        syn::parse_file(&production_chirho).expect("parse ordinary-term proof owner");
    let proof_struct_chirho = syntax_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            syn::Item::Struct(struct_chirho)
                if struct_chirho.ident == ORDINARY_TERM_PROOF_CHIRHO =>
            {
                Some(struct_chirho)
            }
            _ => None,
        })
        .expect("ordinary-term verified proof must remain one production struct");
    assert!(matches!(
        proof_struct_chirho.vis,
        syn::Visibility::Public(_)
    ));
    let fields_chirho = proof_struct_chirho
        .fields
        .iter()
        .map(|field_chirho| {
            assert!(
                matches!(field_chirho.vis, syn::Visibility::Inherited),
                "ordinary-term proof fields must remain private"
            );
            field_chirho
                .ident
                .as_ref()
                .expect("ordinary-term proof field must be named")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        fields_chirho,
        BTreeSet::from([
            "accepted_term_chirho".to_owned(),
            "consistency_group_digest_chirho".to_owned(),
            "holder_receipt_digests_chirho".to_owned(),
            "tail_record_digest_chirho".to_owned(),
            "tail_seq_chirho".to_owned(),
        ]),
        "the ordinary-term private proof gained or lost an authority-bearing coordinate"
    );
    assert!(
        proof_struct_chirho.attrs.iter().all(|attribute_chirho| {
            !attribute_chirho.path().is_ident("derive")
                && !attribute_chirho.path().is_ident("serde")
        }),
        "the ordinary-term proof must not derive construction, deserialization, or field traversal"
    );

    let proof_impls_chirho = syntax_chirho
        .items
        .iter()
        .filter_map(|item_chirho| match item_chirho {
            syn::Item::Impl(implementation_chirho)
                if matches!(implementation_chirho.self_ty.as_ref(), syn::Type::Path(path_chirho)
                        if path_chirho.path.segments.last().is_some_and(|segment_chirho| segment_chirho.ident == ORDINARY_TERM_PROOF_CHIRHO)) =>
            {
                Some(implementation_chirho)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        proof_impls_chirho.len(),
        1,
        "the ordinary-term proof must have one inherent implementation and no trait-based laundering surface"
    );
    let proof_impl_chirho = proof_impls_chirho[0];
    assert!(
        proof_impl_chirho.trait_.is_none(),
        "the ordinary-term proof must not implement From, Default, Deserialize, or another construction trait"
    );
    let verify_chirho = proof_impl_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            syn::ImplItem::Fn(function_chirho) if function_chirho.sig.ident == "verify_chirho" => {
                Some(function_chirho)
            }
            _ => None,
        })
        .expect("ordinary-term proof must retain one verifying constructor");
    let mut constructions_chirho = ProofConstructionVisitorChirho::default();
    constructions_chirho.visit_block(&verify_chirho.block);
    assert_eq!(
        constructions_chirho.self_structs_chirho, 1,
        "the ordinary-term proof must have exactly one construction in its full verifier"
    );
}
