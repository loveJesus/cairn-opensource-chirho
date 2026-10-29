// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Brick #5's structural half: the test-kind fence sits on the three PRODUCTION resident-actor doors
//! and on neither compensation-provider door; the credits-demo setup road also refuses the marker
//! before its own mutations.
//!
//! **Why this needs a guard rather than review.** The five openers differ by a few words, they live
//! close together, and all five delegate to one private funnel — so moving the fence
//! call "up into the shared function" reads like a tidy-up and is in fact the whole regression: it
//! would deny the hosted item-6 drill the marker exists to permit. Moving it OFF a production door
//! is the opposite regression and reads like a merge accident. A caller SET (not a count) names
//! whichever one happened, in the failure message.
//!
//! **HONEST SCOPE.** This guard is about which functions carry the CALL. It says nothing about
//! whether a test-kind issuer can reach production — that is custody (the pin is derived from a
//! pre-provisioned secret), and no source census can establish it. It also cannot see a fence
//! removed by deleting the fence FUNCTION itself; the positive control below fails loudly in that
//! case instead, by asserting the definition is present before any absence assertion runs.

use super::cf6_regenesis_guard_tests_chirho::{
    attributes_are_test_only_chirho, REGENESIS_CRATE_CHIRHO,
};
use super::{production_text_chirho, workspace_production_rs_files_chirho, workspace_root_chirho};
use std::collections::BTreeSet;
use syn::visit::Visit;

/// The fence the three production doors must call.
const FENCE_FUNCTION_CHIRHO: &str = "refuse_test_kind_marked_host_config_chirho";

/// The three PRODUCTION resident-actor openers: provider-less, and therefore the doors a shipping
/// binary reaches. All must carry the fence.
const PRODUCTION_DOORS_CHIRHO: [&str; 3] = [
    "open_resident_effect_journal_handle_chirho",
    "open_resident_effect_journal_handle_with_shared_elector_chirho",
    "open_resident_effect_journal_handle_with_shared_elector_and_capacity_admission_chirho",
];

/// The two compensation-provider openers. They are the test-kind widening (their caller population
/// is confined by `gd7_compensation_provider_door_has_no_shipping_binary_caller_chirho`), so the
/// fence must NOT reach them — a drill authored in test-kind mode opens through one of these.
///
/// Named here as strings rather than by importing the sibling guard's needles, because those are
/// CALL-form needles with a trailing `(` and this guard reasons about function DEFINITION names.
const PROVIDER_DOORS_CHIRHO: [&str; 2] = [
    "open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho",
    "open_resident_effect_journal_handle_with_shared_elector_and_gd7_compensation_provider_chirho",
];

/// The shipping seeding road performs the same refusal at setup entry, before H3 mutation. This
/// is intentionally admitted alongside the two resident doors: it refuses the marked config and
/// never names a provider door.
const EARLY_SETUP_FENCE_CALLER_CHIRHO: &str = "run_credits_demo_setup_chirho";

/// The module that defines all five doors, plus the private funnel all five delegate into. The
/// funnel is named because "the fence moved into the funnel" is the specific tidy-up this guard
/// exists to catch.
const DOOR_MODULE_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-host-chirho/src/resident_authority_chirho/runtime_actor_chirho.rs";
const SHARED_FUNNEL_CHIRHO: &str = "open_resident_effect_journal_handle_with_election_chirho";

/// Which production functions call the fence, resolved through the AST. Keyed by the enclosing
/// function's NAME rather than by file, because the whole claim is about which of five
/// same-file, same-shape openers carries the call.
#[derive(Default)]
struct FenceCallerVisitorChirho {
    current_function_chirho: Option<String>,
    callers_chirho: BTreeSet<String>,
    /// Positive control: every function this walk entered at all. An empty set means the visitor
    /// never ran, which would make the absence assertions below vacuous.
    visited_functions_chirho: BTreeSet<String>,
}

impl FenceCallerVisitorChirho {
    fn enter_chirho(&mut self, name_chirho: String, block_chirho: &syn::Block) {
        self.visited_functions_chirho.insert(name_chirho.clone());
        let prior_chirho = self.current_function_chirho.replace(name_chirho);
        self.visit_block(block_chirho);
        self.current_function_chirho = prior_chirho;
    }
}

impl<'ast_chirho> Visit<'ast_chirho> for FenceCallerVisitorChirho {
    fn visit_item_fn(&mut self, function_chirho: &'ast_chirho syn::ItemFn) {
        if attributes_are_test_only_chirho(&function_chirho.attrs) {
            return;
        }
        self.enter_chirho(
            function_chirho.sig.ident.to_string(),
            &function_chirho.block,
        );
    }

    fn visit_impl_item_fn(&mut self, function_chirho: &'ast_chirho syn::ImplItemFn) {
        if attributes_are_test_only_chirho(&function_chirho.attrs) {
            return;
        }
        self.enter_chirho(
            function_chirho.sig.ident.to_string(),
            &function_chirho.block,
        );
    }

    fn visit_item_mod(&mut self, module_chirho: &'ast_chirho syn::ItemMod) {
        if attributes_are_test_only_chirho(&module_chirho.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, module_chirho);
    }

    fn visit_item_impl(&mut self, implementation_chirho: &'ast_chirho syn::ItemImpl) {
        if attributes_are_test_only_chirho(&implementation_chirho.attrs) {
            return;
        }
        syn::visit::visit_item_impl(self, implementation_chirho);
    }

    fn visit_expr_call(&mut self, call_chirho: &'ast_chirho syn::ExprCall) {
        if let syn::Expr::Path(path_chirho) = call_chirho.func.as_ref() {
            if path_chirho
                .path
                .segments
                .last()
                .is_some_and(|segment_chirho| segment_chirho.ident == FENCE_FUNCTION_CHIRHO)
            {
                self.callers_chirho.insert(
                    self.current_function_chirho
                        .clone()
                        .unwrap_or_else(|| "<outside-function-chirho>".to_owned()),
                );
            }
        }
        syn::visit::visit_expr_call(self, call_chirho);
    }
}

/// THE BRICK-#5 INVARIANT, executed: the three production doors and the early setup road call the
/// fence; neither compensation-provider door does.
#[test]
fn the_test_kind_fence_guards_exactly_the_three_production_resident_actor_doors_chirho() {
    let root_chirho = workspace_root_chirho();
    let door_source_chirho =
        std::fs::read_to_string(root_chirho.join(DOOR_MODULE_CHIRHO)).expect("read door module");

    // POSITIVE CONTROLS, run BEFORE any absence assertion: all five names this guard reasons about
    // must exist, or a rename would silently turn every check below into a vacuous pass.
    for door_chirho in PRODUCTION_DOORS_CHIRHO.iter().chain(&PROVIDER_DOORS_CHIRHO) {
        assert!(
            door_source_chirho.contains(&format!("pub fn {door_chirho}(")),
            "a resident-actor door this guard reasons about is missing or renamed: {door_chirho}"
        );
    }
    assert!(
        door_source_chirho.contains(&format!("fn {SHARED_FUNNEL_CHIRHO}(")),
        "the shared resident-actor funnel is missing or renamed: {SHARED_FUNNEL_CHIRHO}"
    );

    let mut visitor_chirho = FenceCallerVisitorChirho::default();
    for path_chirho in workspace_production_rs_files_chirho() {
        let raw_source_chirho =
            std::fs::read_to_string(&path_chirho).expect("read production source");
        let Ok(syntax_chirho) = syn::parse_file(&production_text_chirho(&raw_source_chirho)) else {
            continue;
        };
        visitor_chirho.visit_file(&syntax_chirho);
    }
    assert!(
        visitor_chirho
            .visited_functions_chirho
            .contains(SHARED_FUNNEL_CHIRHO),
        "the AST walk never reached the resident-actor module (positive control): every absence \
         assertion below would be vacuous"
    );

    let mut expected_chirho: BTreeSet<String> = PRODUCTION_DOORS_CHIRHO
        .iter()
        .map(|door_chirho| (*door_chirho).to_owned())
        .collect();
    expected_chirho.insert(EARLY_SETUP_FENCE_CALLER_CHIRHO.to_owned());
    assert_eq!(
        visitor_chirho.callers_chirho, expected_chirho,
        "the test-kind fence's production caller set changed. A MISSING production door means a \
         shipping composition can now open the elected write/mint authority from a config authored \
         for a synthetic test kind. The admitted early setup caller refuses before H3 mutation. An \
         EXTRA caller — especially {SHARED_FUNNEL_CHIRHO} or a compensation-provider door — means \
         the fence reached the test-kind opener and every hosted drill authored in test-kind mode is \
         now refused."
    );

    // Said again as its own assertion rather than left implicit in the set equality: this is the
    // half that keeps the drill alive, and a reader scanning for it should find it by name.
    for provider_door_chirho in PROVIDER_DOORS_CHIRHO {
        assert!(
            !visitor_chirho.callers_chirho.contains(provider_door_chirho),
            "the test-kind fence reached a compensation-provider door: {provider_door_chirho}"
        );
    }
}

/// The design's "source census extension" for brick #5, discharged as a COVERAGE check rather than
/// as a second copy of the census.
///
/// `regenesis_operator_source_has_no_ambient_or_generated_key_road_chirho` already scans every
/// top-level `src/*.rs` of the regenesis crate for `OsRng` / `::generate` / `set_secret_chirho(`,
/// and its sibling directory tripwire keeps the crate's only `src/` subdirectory the all-test one.
/// So the new authoring-mode module is covered by construction — PROVIDED it is a top-level file.
/// That proviso is the whole content of this test: re-implementing the token scan here would give
/// the never-generate law a second home that could drift from the first.
#[test]
fn the_authoring_mode_module_sits_inside_the_regenesis_never_generate_census_chirho() {
    let module_chirho = workspace_root_chirho()
        .join(REGENESIS_CRATE_CHIRHO)
        .join("src")
        .join("ledger_host_authoring_mode_chirho.rs");
    assert!(
        module_chirho.is_file(),
        "brick #5's authoring-mode module is not a top-level regenesis src file, so the crate's \
         ambient/never-generate census (which reads only top-level src/*.rs) no longer covers it: \
         {}",
        module_chirho.display()
    );
}
