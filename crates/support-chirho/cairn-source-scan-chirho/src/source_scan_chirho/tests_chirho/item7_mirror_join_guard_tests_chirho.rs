// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Item 7.2a money/authority guards for the mirror receiver's two-authority JOIN seam.
//!
//! Two properties this crate's own tests cannot pin, because both are about what the source must NOT
//! contain and about there being exactly ONE producer:
//!
//! - **F1** — the mirror receiver must never consult its OWN `is_leader_chirho`. That bit means "am I
//!   the leader", which is false by construction for a follower storing on behalf of the leader, so
//!   requiring it would refuse every legitimate mirror prepare once a real elector view is wired.
//! - **F3** — the roster half and the leadership half must reach the authority check as ONE joined
//!   value, and a joined view's term must have exactly one writer, so a roster/leadership term
//!   disagreement is unrepresentable rather than checked.
//! - **Route census limit** — the positive route map proves every currently routed handler can reach
//!   its reviewed gate. It does not prove control-flow dominance: a future pre-gate early return
//!   would survive. Typed verified axum extractors remain the type-tier successor for that property.
//!
//! Every comparison here is made on COMMENT-STRIPPED, WHITESPACE-NORMALIZED text. Comments are
//! stripped because the production body deliberately explains in prose why it does not consult
//! `is_leader_chirho`, and a naive search would read that explanation as the violation it forbids.
//! Whitespace is normalized because rustfmt chooses where to break a long expression, and a guard
//! keyed to one particular line break would go quietly green after a reformat.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use syn::visit::Visit;

const MIRROR_AUTHORITY_SOURCE_CHIRHO: &str =
    "crates/support-chirho/cairn-mirror-chirho/src/authority_chirho.rs";
const MIRROR_MEMBERSHIP_SOURCE_CHIRHO: &str =
    "crates/support-chirho/cairn-mirror-chirho/src/membership_chirho.rs";
const AUTHORITY_FN_CHIRHO: &str = "pub fn verify_mirror_prepare_authority_chirho<'frame_chirho>(";
const RECEIVER_LEADER_BINDING_FN_CHIRHO: &str =
    "pub fn verify_mirror_receiver_elected_leader_chirho(";

fn read_source_chirho(relative_chirho: &str) -> String {
    std::fs::read_to_string(workspace_root_chirho().join(relative_chirho))
        .unwrap_or_else(|_| panic!("read {relative_chirho}"))
}

/// Strip line comments, then collapse every run of whitespace to one space.
fn code_text_chirho(text_chirho: &str) -> String {
    let uncommented_chirho = text_chirho
        .lines()
        .map(|line_chirho| match line_chirho.find("//") {
            Some(index_chirho) => &line_chirho[..index_chirho],
            None => line_chirho,
        })
        .collect::<Vec<_>>()
        .join("\n");
    uncommented_chirho
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The production CODE of the authority function, from its signature to its closing brace. Test code
/// is stripped first so a `cfg(test)` mirror of the predicate cannot be mistaken for the production
/// one.
fn authority_binding_production_body_chirho(source_chirho: &str) -> String {
    let production_chirho = production_text_chirho(source_chirho).into_owned();
    let after_signature_chirho = production_chirho
        .split(RECEIVER_LEADER_BINDING_FN_CHIRHO)
        .nth(1)
        .expect("the mirror authority binding must remain one resolved helper")
        .to_string();
    let body_chirho = after_signature_chirho
        .split("\n}\n")
        .next()
        .expect("bounded authority function body");
    code_text_chirho(body_chirho)
}

#[derive(Default)]
struct ReceiverAuthorityReferencePopulationChirho {
    elected_leader_accessors_chirho: usize,
    shared_receiver_verifiers_chirho: usize,
}

#[derive(Default)]
struct ReceiverRoutePopulationChirho {
    routes_chirho: BTreeMap<String, String>,
}

impl<'ast_chirho> Visit<'ast_chirho> for ReceiverRoutePopulationChirho {
    fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
        if call_chirho.method == "route" {
            let mut arguments_chirho = call_chirho.args.iter();
            let route_chirho = arguments_chirho
                .next()
                .and_then(expression_symbol_chirho)
                .expect("every mirror receiver route must use a resolvable path symbol");
            let handler_chirho = arguments_chirho
                .next()
                .and_then(post_handler_symbol_chirho)
                .expect("every mirror receiver route must use post(handler_chirho)");
            assert!(
                arguments_chirho.next().is_none(),
                "mirror receiver route gained an unexpected argument"
            );
            assert!(
                self.routes_chirho
                    .insert(route_chirho.clone(), handler_chirho)
                    .is_none(),
                "duplicate mirror receiver route in AST census: {route_chirho}"
            );
        }
        syn::visit::visit_expr_method_call(self, call_chirho);
    }
}

fn expression_symbol_chirho(expression_chirho: &syn::Expr) -> Option<String> {
    match expression_chirho {
        syn::Expr::Path(path_chirho) => path_chirho
            .path
            .segments
            .last()
            .map(|segment_chirho| segment_chirho.ident.to_string()),
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(value_chirho),
            ..
        }) => Some(value_chirho.value()),
        _ => None,
    }
}

fn post_handler_symbol_chirho(expression_chirho: &syn::Expr) -> Option<String> {
    let syn::Expr::Call(post_chirho) = expression_chirho else {
        return None;
    };
    if expression_symbol_chirho(&post_chirho.func)? != "post" || post_chirho.args.len() != 1 {
        return None;
    }
    expression_symbol_chirho(post_chirho.args.first()?)
}

#[derive(Default)]
struct FunctionCallGraphNodeChirho {
    direct_calls_chirho: BTreeSet<String>,
    references_chirho: BTreeSet<String>,
}

impl<'ast_chirho> Visit<'ast_chirho> for FunctionCallGraphNodeChirho {
    fn visit_expr_call(&mut self, call_chirho: &'ast_chirho syn::ExprCall) {
        if let Some(symbol_chirho) = expression_symbol_chirho(&call_chirho.func) {
            self.direct_calls_chirho.insert(symbol_chirho.clone());
            self.references_chirho.insert(symbol_chirho);
        }
        syn::visit::visit_expr_call(self, call_chirho);
    }

    fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
        self.references_chirho
            .insert(call_chirho.method.to_string());
        syn::visit::visit_expr_method_call(self, call_chirho);
    }

    fn visit_expr_path(&mut self, path_chirho: &'ast_chirho syn::ExprPath) {
        if let Some(segment_chirho) = path_chirho.path.segments.last() {
            self.references_chirho
                .insert(segment_chirho.ident.to_string());
        }
        syn::visit::visit_expr_path(self, path_chirho);
    }
}

fn reachable_function_references_chirho(
    graph_chirho: &BTreeMap<String, FunctionCallGraphNodeChirho>,
    root_chirho: &str,
) -> BTreeSet<String> {
    let mut pending_chirho = vec![root_chirho.to_string()];
    let mut visited_chirho = BTreeSet::new();
    let mut references_chirho = BTreeSet::new();
    while let Some(function_chirho) = pending_chirho.pop() {
        if !visited_chirho.insert(function_chirho.clone()) {
            continue;
        }
        let node_chirho = graph_chirho
            .get(&function_chirho)
            .unwrap_or_else(|| panic!("routed mirror handler disappeared: {function_chirho}"));
        references_chirho.extend(node_chirho.references_chirho.iter().cloned());
        pending_chirho.extend(
            node_chirho
                .direct_calls_chirho
                .iter()
                .filter(|callee_chirho| graph_chirho.contains_key(*callee_chirho))
                .cloned(),
        );
    }
    references_chirho
}

impl<'ast_chirho> Visit<'ast_chirho> for ReceiverAuthorityReferencePopulationChirho {
    fn visit_expr_method_call(&mut self, call_chirho: &'ast_chirho syn::ExprMethodCall) {
        if call_chirho.method == "elected_leader_node_id_chirho" {
            self.elected_leader_accessors_chirho += 1;
        }
        syn::visit::visit_expr_method_call(self, call_chirho);
    }

    fn visit_expr_path(&mut self, path_chirho: &'ast_chirho syn::ExprPath) {
        if path_chirho
            .path
            .segments
            .last()
            .is_some_and(|segment_chirho| {
                segment_chirho.ident == "verify_mirror_receiver_elected_leader_chirho"
            })
        {
            self.shared_receiver_verifiers_chirho += 1;
        }
        syn::visit::visit_expr_path(self, path_chirho);
    }
}

#[test]
fn mirror_receiver_authority_never_consults_its_own_is_leader_bit_chirho() {
    let source_chirho = read_source_chirho(MIRROR_AUTHORITY_SOURCE_CHIRHO);
    let body_chirho = authority_binding_production_body_chirho(&source_chirho);
    assert!(
        !body_chirho.contains("is_leader_chirho"),
        "the mirror receiver is a FOLLOWER: consulting its own is_leader would refuse every legitimate mirror prepare (reviewer F1)"
    );
    assert!(
        body_chirho.contains("elected_leader_node_id_chirho()")
            && body_chirho.contains("bound_term_chirho != joined_chirho.term_chirho()"),
        "the shared receiver verifier must still bind sender identity and the exact joined term"
    );
    // The relay's predicate must never reappear in the mirror's production authority path.
    assert!(
        !body_chirho.contains("Some(receiver_node_id_chirho)"),
        "`leader_id == self` is the relay's predicate and is FALSE for every legitimate mirror prepare"
    );
}

#[test]
fn mirror_authority_takes_one_joined_view_never_a_separate_leadership_chirho() {
    let source_chirho = read_source_chirho(MIRROR_AUTHORITY_SOURCE_CHIRHO);
    let production_chirho = production_text_chirho(&source_chirho).into_owned();
    let signature_chirho = code_text_chirho(
        production_chirho
            .split(AUTHORITY_FN_CHIRHO)
            .nth(1)
            .expect("the mirror authority entry point must keep its reviewed signature")
            .split(") -> Result<")
            .next()
            .expect("bounded authority signature"),
    );
    assert!(
        signature_chirho.contains("joined_chirho: &JoinedMirrorViewChirho"),
        "the roster and leadership halves must arrive as ONE joined value (reviewer F3)"
    );
    assert!(
        !signature_chirho.contains("LeadershipChirho"),
        "a separate leadership argument re-opens the F3 hole: a caller could pair a view with a leadership it was never joined to"
    );
    assert!(
        !signature_chirho.contains("MirrorMembershipViewChirho"),
        "a separate membership-view argument re-opens the F3 hole for the same reason"
    );
}

#[test]
fn a_joined_mirror_view_has_exactly_one_producer_and_one_term_writer_chirho() {
    let source_chirho = read_source_chirho(MIRROR_MEMBERSHIP_SOURCE_CHIRHO);
    let production_raw_chirho = production_text_chirho(&source_chirho).into_owned();
    let production_chirho = code_text_chirho(&production_raw_chirho);

    // The membership view's constructor is private and single-purpose, so no caller can name a term.
    assert!(
        production_chirho.contains("fn from_join_chirho("),
        "the membership view constructor must stay present and private to the join"
    );
    assert!(
        !production_chirho.contains("pub fn from_join_chirho(")
            && !production_chirho.contains("pub(crate) fn from_join_chirho("),
        "publishing the membership-view constructor would let a caller name a term the election never observed"
    );
    assert_eq!(
        production_chirho
            .matches("MirrorMembershipViewChirho::from_join_chirho(")
            .count(),
        1,
        "a joined view must have exactly one producer; a second call site is a second term writer"
    );

    let constructor_signature_chirho = production_chirho
        .split("fn from_join_chirho(")
        .nth(1)
        .expect("the private joined-view constructor")
        .split(") -> Result<")
        .next()
        .expect("bounded constructor signature");
    assert!(
        constructor_signature_chirho.contains(
            "placement_chirho: &VerifiedTenantPlacementChirho, observation_chirho: &MirrorElectionObservationChirho,"
        ),
        "the joined view must take verified placement plus one election observation, never a caller-supplied term"
    );
    assert!(
        !constructor_signature_chirho.contains("term_chirho"),
        "the joined-view constructor must not accept a separately supplied term"
    );

    // The join reads the live election ONCE: two reads could straddle an election and join a leader
    // from one instant to a population from another.
    let join_body_chirho = production_chirho
        .split("pub fn join_mirror_view_chirho(")
        .nth(1)
        .expect("the two-authority join");
    assert_eq!(
        join_body_chirho
            .matches("observe_election_chirho()")
            .count(),
        1,
        "the join must take exactly one election observation"
    );
    assert_eq!(
        production_chirho
            .matches("term_chirho: observation_chirho.leadership_chirho.term_chirho,")
            .count(),
        1,
        "the joined view's term must have one exact write from the single election observation"
    );

    let production_implementors_chirho = workspace_production_rs_files_chirho()
        .into_iter()
        .map(|path_chirho| {
            let source_chirho =
                std::fs::read_to_string(path_chirho).expect("read production source");
            production_text_chirho(&source_chirho)
                .matches("impl MirrorLeadershipViewChirho for")
                .count()
        })
        .sum::<usize>();
    assert_eq!(
        production_implementors_chirho, 1,
        "one production adapter must attenuate the one running elector into the mirror observation port"
    );
}

#[test]
fn every_receiver_leader_binding_uses_the_shared_follower_safe_verifier_chirho() {
    let mut elected_leader_accessors_chirho = BTreeMap::new();
    let mut shared_receiver_verifiers_chirho = BTreeMap::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let source_chirho = std::fs::read_to_string(&path_chirho)
            .unwrap_or_else(|_| panic!("read {}", workspace_relative_chirho(&path_chirho)));
        let production_chirho = production_text_chirho(&source_chirho);
        let syntax_chirho = syn::parse_file(&production_chirho)
            .unwrap_or_else(|_| panic!("parse {}", workspace_relative_chirho(&path_chirho)));
        let mut population_chirho = ReceiverAuthorityReferencePopulationChirho::default();
        population_chirho.visit_file(&syntax_chirho);
        let relative_chirho = workspace_relative_chirho(&path_chirho);
        if population_chirho.elected_leader_accessors_chirho > 0 {
            elected_leader_accessors_chirho.insert(
                relative_chirho.clone(),
                population_chirho.elected_leader_accessors_chirho,
            );
        }
        if population_chirho.shared_receiver_verifiers_chirho > 0 {
            shared_receiver_verifiers_chirho.insert(
                relative_chirho,
                population_chirho.shared_receiver_verifiers_chirho,
            );
        }
    }
    assert_eq!(
        elected_leader_accessors_chirho,
        BTreeMap::from([
            (MIRROR_AUTHORITY_SOURCE_CHIRHO.to_string(), 1),
            // C5 B3-a3 (item 14 D3): the one SENDER predicate, `local_sender_is_elected_leader_chirho`.
            // The ledger mirror's sender (Door A) used to make this read itself, in
            // `cairn-ledger-mirror-http-chirho/src/client_chirho.rs`. It now calls the predicate, and so does
            // erasure propagation. A sender checking its OWN leadership is the legitimate read. Receivers
            // still bind only through the shared follower-safe verifier, which the second map below pins.
            (MIRROR_MEMBERSHIP_SOURCE_CHIRHO.to_string(), 1),
            (
                "crates/stores-chirho/cairn-ledger-mirror-http-chirho/src/recovery_chirho/port_chirho.rs"
                    .to_string(),
                2,
            ),
        ]),
        "direct elected-leader reads are a reviewed production population; receiver binders must use the shared verifier so the follower's own is_leader bit cannot recur"
    );
    assert_eq!(
        shared_receiver_verifiers_chirho,
        BTreeMap::from([
            (MIRROR_AUTHORITY_SOURCE_CHIRHO.to_string(), 1),
            (
                "crates/stores-chirho/cairn-ledger-mirror-http-chirho/src/server_chirho.rs"
                    .to_string(),
                4,
            ),
            // C5 B1 (item 7.2c): two LEADER-side self-checks use the same verifier to prove the
            // confirming or attesting node is its own joined view's elected leader at that view's
            // term. They are not receiver bindings; custody and erasure frames reach the receiver
            // check through `verify_mirror_authority_binding_chirho` in the authority source.
            (
                "crates/support-chirho/cairn-key-custody-chirho/src/custody_chirho/receipt_chirho.rs"
                    .to_string(),
                1,
            ),
            (
                "crates/support-chirho/cairn-key-custody-chirho/src/erasure_chirho/decommission_chirho.rs"
                    .to_string(),
                1,
            ),
        ]),
        "every receiver-side authority binding must resolve through the one follower-safe verifier"
    );
}

#[test]
fn every_routed_mirror_receiver_request_reaches_its_positive_verification_gate_chirho() {
    const MIRROR_SERVER_SOURCE_CHIRHO: &str =
        "crates/stores-chirho/cairn-ledger-mirror-http-chirho/src/server_chirho.rs";
    let source_chirho = read_source_chirho(MIRROR_SERVER_SOURCE_CHIRHO);
    let production_chirho = production_text_chirho(&source_chirho);
    let syntax_chirho = syn::parse_file(&production_chirho).expect("parse mirror receiver server");
    let router_chirho = syntax_chirho
        .items
        .iter()
        .find_map(|item_chirho| match item_chirho {
            syn::Item::Fn(function_chirho)
                if function_chirho.sig.ident == "ledger_mirror_router_chirho" =>
            {
                Some(function_chirho)
            }
            _ => None,
        })
        .expect("mirror receiver router must remain a resolved production function");
    let mut route_population_chirho = ReceiverRoutePopulationChirho::default();
    route_population_chirho.visit_block(&router_chirho.block);
    let expected_routes_chirho = BTreeMap::from([
        (
            "LEDGER_MIRROR_PREPARE_PATH_CHIRHO".to_string(),
            "prepare_handler_chirho".to_string(),
        ),
        (
            "LEDGER_MIRROR_FINALIZE_PATH_CHIRHO".to_string(),
            "finalize_handler_chirho".to_string(),
        ),
        (
            "LEDGER_MIRROR_RECOVERY_HEAD_PATH_CHIRHO".to_string(),
            "recovery_head_handler_chirho".to_string(),
        ),
        (
            "LEDGER_MIRROR_ORDINARY_TERM_ACCEPTANCE_PATH_CHIRHO".to_string(),
            "ordinary_term_acceptance_handler_chirho".to_string(),
        ),
        (
            "LEDGER_MIRROR_PREFIX_BEGIN_PATH_CHIRHO".to_string(),
            "prefix_begin_handler_chirho".to_string(),
        ),
        (
            "LEDGER_MIRROR_PREFIX_PAGE_PATH_CHIRHO".to_string(),
            "prefix_page_handler_chirho".to_string(),
        ),
        (
            "LEDGER_MIRROR_PREFIX_SEAL_PATH_CHIRHO".to_string(),
            "prefix_seal_handler_chirho".to_string(),
        ),
    ]);
    assert_eq!(
        route_population_chirho.routes_chirho, expected_routes_chirho,
        "the complete follower route population is reviewed; a new raw-body endpoint must name and pin its positive verification gate"
    );

    let mut graph_chirho = BTreeMap::new();
    for item_chirho in &syntax_chirho.items {
        let syn::Item::Fn(function_chirho) = item_chirho else {
            continue;
        };
        let mut node_chirho = FunctionCallGraphNodeChirho::default();
        node_chirho.visit_block(&function_chirho.block);
        graph_chirho.insert(function_chirho.sig.ident.to_string(), node_chirho);
    }
    let required_references_chirho = BTreeMap::from([
        (
            "prepare_handler_chirho",
            vec![
                "decode_and_authenticate_mirror_prepare_chirho",
                "verify_mirror_prepare_authority_chirho",
            ],
        ),
        (
            "finalize_handler_chirho",
            vec![
                "decode_and_verify_mirror_finalize_chirho",
                "verify_mirror_finalize_authority_chirho",
            ],
        ),
        (
            "recovery_head_handler_chirho",
            vec![
                "decode_and_verify_chirho",
                "verify_mirror_receiver_elected_leader_chirho",
                "load_recovery_source_head_chirho",
            ],
        ),
        (
            "ordinary_term_acceptance_handler_chirho",
            vec![
                "decode_and_verify_chirho",
                "verify_mirror_receiver_elected_leader_chirho",
                "load_high_water_chirho",
                "sign_chirho",
            ],
        ),
        (
            "prefix_begin_handler_chirho",
            vec![
                "decode_and_verify_chirho",
                "verify_prefix_manifest_authority_chirho",
                "begin_verified_prefix_chirho",
            ],
        ),
        (
            "prefix_page_handler_chirho",
            vec!["decode_chirho", "store_verified_prefix_page_chirho"],
        ),
        (
            "prefix_seal_handler_chirho",
            vec![
                "decode_and_verify_chirho",
                "verify_prefix_manifest_authority_chirho",
                "prepare_bootstrap_commit_chirho",
                "commit_bootstrap_chirho",
            ],
        ),
    ]);
    for (handler_chirho, required_chirho) in required_references_chirho {
        let reachable_chirho = reachable_function_references_chirho(&graph_chirho, handler_chirho);
        for reference_chirho in required_chirho {
            assert!(
                reachable_chirho.contains(reference_chirho),
                "routed mirror receiver handler {handler_chirho} no longer reaches required positive gate {reference_chirho}: {reachable_chirho:?}; this census proves reachability, not dominance, so a pre-gate early return remains outside its claim until typed verified extractors land"
            );
        }
    }
}
